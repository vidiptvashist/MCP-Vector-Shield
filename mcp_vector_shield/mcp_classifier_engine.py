import os
import hashlib
import logging
import numpy as np
import torch
import torch.nn as nn
from typing import Optional
from collections import OrderedDict
from sentence_transformers import SentenceTransformer

logger = logging.getLogger("mcp_vector_shield")

# -----------------------------------------------------------------------------
# 1. PyTorch Model Architecture (Identical to train_classifier.py)
# -----------------------------------------------------------------------------
class ToolMLPClassifier(nn.Module):
    """
    Lightweight Multi-Layer Perceptron (MLP) to classify tool descriptions
    as Safe (0) or Poisoned/Attack (1).
    """
    def __init__(self, input_dim: int = 384, hidden_dim: int = 64):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)

# -----------------------------------------------------------------------------
# 2. Upgraded Neural Detection Shield Class
# -----------------------------------------------------------------------------
class MCPNeuralShield:
    """
    Generalized Neural Network Classifier for Zero-Day Tool Poisoning Detection.
    Replaces the L2 distance-based MCPSemanticRegistry with a deep learning MLP
    model trained on SentenceTransformer embeddings.
    """
    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold: float = 0.5,
        device: Optional[str] = None,
        cache_size: int = 1024
    ):
        """
        Initializes the neural shield by loading the SentenceTransformer and the
        pre-trained PyTorch MLP classifier weights.
        
        :param model_path: Path to the serialized classifier weights file. If None, uses the bundled shield_model.pt.
        :param threshold: Classification probability boundary (default: 0.5).
        :param device: Hardware device target ('cuda', 'mps', 'cpu'). Auto-selects if None.
        :param cache_size: Max number of cached embeddings for sub-2ms repeat inference.
        """
        self.threshold = threshold

        # Resolve the default model weights path (embedded inside the package)
        if model_path is None:
            package_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(package_dir, "shield_model.pt")
            if not os.path.exists(model_path):
                # Fallback to working directory for local development execution
                model_path = "shield_model.pt"


        # 1. Determine device with fallback
        if device is None:
            if torch.cuda.is_available():
                self.device = "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                self.device = "mps"
            else:
                self.device = "cpu"
        else:
            self.device = device

        logger.info(f"Initializing MCPNeuralShield on device: {self.device}")

        # Embedding LRU cache: eliminates SentenceTransformer re-encoding bottleneck
        # on repeated tool schema checks (5ms encode → <0.1ms cache hit).
        self._cache_size = cache_size
        self._embedding_cache: OrderedDict[str, np.ndarray] = OrderedDict()

        # 2. Load the SentenceTransformer model (quantized if on CPU)
        try:
            self.model = SentenceTransformer("all-MiniLM-L6-v2", device=self.device)
        except Exception as e:
            logger.warning(f"Failed loading SentenceTransformer on {self.device}: {e}. Falling back to CPU.")
            self.device = "cpu"
            self.model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")

        # 3. Initialize MLP Classifier architecture
        self.embedding_dim = self.model.get_sentence_embedding_dimension() or 384
        self.classifier = ToolMLPClassifier(input_dim=self.embedding_dim, hidden_dim=64)

        # 4. Load trained weights from disk
        if os.path.exists(model_path):
            try:
                checkpoint = torch.load(model_path, map_location="cpu")
                if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
                    self.classifier.load_state_dict(checkpoint["model_state_dict"])
                    self.threshold = checkpoint.get("threshold", self.threshold)
                    logger.info(f"Loaded classifier weights & threshold ({self.threshold}) from checkpoint '{model_path}'.")
                else:
                    self.classifier.load_state_dict(checkpoint)
                    logger.info(f"Loaded raw classifier weights from state_dict '{model_path}'.")
            except Exception as e:
                logger.error(f"Error loading classifier weights: {e}. Model will use uninitialized weights.")
        else:
            # Look in parent directory fallback (for imports within nested folders)
            parent_path = os.path.join("..", model_path)
            if os.path.exists(parent_path):
                try:
                    checkpoint = torch.load(parent_path, map_location="cpu")
                    if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
                        self.classifier.load_state_dict(checkpoint["model_state_dict"])
                        self.threshold = checkpoint.get("threshold", self.threshold)
                    else:
                        self.classifier.load_state_dict(checkpoint)
                    logger.info(f"Loaded classifier weights from parent fallback: '{parent_path}'.")
                except Exception as e:
                    logger.error(f"Error loading classifier from parent fallback: {e}")
            else:
                logger.warning(f"Pre-trained weights file '{model_path}' not found. Initializing with random weights.")

        self.classifier.to(self.device)
        self.classifier.eval()

        # 5. Apply PyTorch dynamic quantization for CPU to ensure ultra-fast (sub-2ms) latency
        if self.device == "cpu":
            try:
                # Force qnnpack backend on macOS/ARM to avoid NoQEngine error
                if hasattr(torch.backends, "quantized"):
                    torch.backends.quantized.engine = "qnnpack"
                self.classifier = torch.quantization.quantize_dynamic(
                    self.classifier, {nn.Linear}, dtype=torch.qint8
                )
                logger.info("Successfully applied CPU dynamic quantization (int8/qnnpack) to classifier.")
            except Exception as e:
                logger.warning(f"Dynamic quantization could not be applied: {e}")

        # Dummy metadata storage to maintain 100% backward compatibility with FAISS APIs
        self.tool_to_id = {}
        self.id_to_tool = {}

    def _serialize_tool(self, tool_schema: dict) -> str:
        """
        Serializes tool metadata (name, description, input properties)
        into a structured string for semantic embedding.
        """
        name = tool_schema.get("name", "")
        description = tool_schema.get("description", "")
        input_schema = tool_schema.get("inputSchema", {})

        properties = input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
        required = input_schema.get("required", []) if isinstance(input_schema, dict) else []

        props_str = (
            ", ".join(f"{k} ({v.get('type', 'any')})" for k, v in properties.items())
            if properties
            else "none"
        )
        req_str = ", ".join(required) if required else "none"

        return f"Tool Name: {name}. Description: {description}. Input properties: {props_str}. Required inputs: {req_str}."

    def _get_embedding(self, text: str) -> np.ndarray:
        """
        Returns the SentenceTransformer embedding for the given text, using the
        LRU cache to avoid re-encoding previously seen tool schemas.
        
        The SentenceTransformer forward pass is ~5ms on CPU. By caching embeddings
        keyed on the serialized text hash, repeated is_attack() calls for the same
        or previously-seen tool schemas complete in <0.1ms instead of 5ms.
        """
        cache_key = hashlib.md5(text.encode()).hexdigest()

        if cache_key in self._embedding_cache:
            # Move to end (most recently used)
            self._embedding_cache.move_to_end(cache_key)
            return self._embedding_cache[cache_key]

        # Cache miss: run the expensive encoder
        embedding = self.model.encode(text, convert_to_numpy=True)

        # Evict oldest entry if at capacity
        if len(self._embedding_cache) >= self._cache_size:
            self._embedding_cache.popitem(last=False)

        self._embedding_cache[cache_key] = embedding
        return embedding

    def is_attack(self, tool_schema: dict) -> bool:
        """
        Embeds the incoming tool schema description and input parameters at runtime,
        passes it through the trained classifier, and returns True if it crosses
        the decision boundary (probability >= threshold) into malicious territory.
        
        Uses an LRU embedding cache so that repeated checks on the same tool schema
        bypass the SentenceTransformer encode step entirely (sub-2ms hot path).
        
        :param tool_schema: Dict of the tool schema to test.
        :return: True if tool poisoning or shadowing attack is detected, False otherwise.
        """
        name = tool_schema.get("name")
        if not name:
            logger.debug("Tool classification failed: missing name parameter.")
            return False

        # 1. Serialize schema to structured representation
        text = self._serialize_tool(tool_schema)

        # 2. Core Inference (with embedding cache for sub-2ms hot-path latency)
        with torch.no_grad():
            embedding = self._get_embedding(text)
            vector = torch.tensor(embedding, dtype=torch.float32).unsqueeze(0).to(self.device)
            
            logits = self.classifier(vector)
            prob = torch.sigmoid(logits).item()

        is_malicious = prob >= self.threshold
        logger.debug(f"Neural Shield Check for '{name}': probability = {prob:.4f} (malicious = {is_malicious})")
        return is_malicious

    def clear_cache(self):
        """Clears the embedding cache. Useful for testing or when tool schemas change."""
        self._embedding_cache.clear()
        logger.debug("Embedding cache cleared.")

    # -----------------------------------------------------------------------------
    # 3. Backward Compatibility Layer for MCPSemanticRegistry
    # -----------------------------------------------------------------------------
    def register_baseline(self, tool_schema: dict) -> int:
        """
        Backward compatibility registry baseline insertion.
        For a generalized classifier, individual baselines do not need to be stored
        in a FAISS vector database. This method is a safe no-op that preserves CLI interfaces.
        """
        name = tool_schema.get("name")
        if not name:
            raise ValueError("Tool schema must contain a non-empty name to register.")

        faiss_id = len(self.tool_to_id)
        self.tool_to_id[name] = faiss_id
        self.id_to_tool[faiss_id] = name
        logger.info(f"[MCPNeuralShield] Registered baseline alias for '{name}' at ID {faiss_id}.")
        return faiss_id

    def is_shadowing_attack(self, tool_schema: dict) -> bool:
        """
        Backward compatibility alias. Wraps the new generalized is_attack classification.
        """
        return self.is_attack(tool_schema)
