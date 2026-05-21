import os

# Configure OpenMP/MKL thread counts to prevent conflicts and segmentation faults on macOS Apple Silicon.
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import logging
import numpy as np
import faiss
import torch
from typing import Optional
from sentence_transformers import SentenceTransformer

logger = logging.getLogger("mcp_vector_shield")


class MCPSemanticRegistry:
    """
    Vector Semantic Registry for MCP tools.
    Uses sentence-transformers to compute embeddings of tool schemas (name + description)
    and FAISS to index and query them, identifying tool shadowing attacks.
    """

    def __init__(self, distance_threshold: float = 1.2, device: Optional[str] = None):
        """
        :param distance_threshold: L2 distance threshold. If the distance to the registered
                                   baseline exceeds this value, a shadowing attack is flagged.
        :param device: Hardware device to use ('cuda', 'mps', 'cpu'). If None, auto-detects.
        """
        self.threshold = distance_threshold

        # 1. Determine device with fallbacks
        if device is None:
            if torch.cuda.is_available():
                self.device = "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                self.device = "mps"
            else:
                self.device = "cpu"
        else:
            self.device = device

        # 2. Load model with fallback to CPU if the target device fails
        try:
            logger.info(f"Initializing SentenceTransformer using device: {self.device}")
            self.model = SentenceTransformer("all-MiniLM-L6-v2", device=self.device)
        except Exception as e:
            logger.warning(
                f"Failed loading SentenceTransformer on {self.device}: {e}. " "Falling back to CPU."
            )
            self.device = "cpu"
            self.model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")

        # 3. Detect dimension and initialize FAISS index
        self.embedding_dim = self.model.get_sentence_embedding_dimension() or 384
        self.index = faiss.IndexFlatL2(self.embedding_dim)

        # 4. Storage for mapping FAISS index IDs to tool names
        self.id_to_tool = {}
        self.tool_to_id = {}
        self.tool_vectors = {}

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

        # Combine parameters to form a holistic description of the tool
        serialized = f"Tool Name: {name}. Description: {description}. Input properties: {props_str}. Required inputs: {req_str}."
        return serialized

    def _vectorize_tool(self, tool_schema: dict) -> np.ndarray:
        """
        Vectorizes the tool schema using SentenceTransformer.
        Returns a float32 numpy array of shape (1, dimension).
        """
        text = self._serialize_tool(tool_schema)
        embedding = self.model.encode(text, convert_to_numpy=True)
        vector = np.array(embedding, dtype="float32")
        if len(vector.shape) == 1:
            vector = np.expand_dims(vector, axis=0)
        return vector

    def register_baseline(self, tool_schema: dict) -> int:
        """
        Registers a tool's baseline schema into the registry.
        Adds its vector to the FAISS index and stores mapping metadata.

        :return: The FAISS ID index assigned to the tool.
        """
        name = tool_schema.get("name")
        if not name:
            raise ValueError("Tool schema must contain a non-empty name to register.")

        vector = self._vectorize_tool(tool_schema)

        # Add vector to FAISS Index
        faiss_id = self.index.ntotal
        self.index.add(vector)

        # Update metadata storage
        self.id_to_tool[faiss_id] = name
        self.tool_to_id[name] = faiss_id
        self.tool_vectors[name] = vector

        logger.info(f"Registered baseline for tool '{name}' at FAISS index ID {faiss_id}.")
        return faiss_id

    def is_shadowing_attack(self, tool_schema: dict) -> bool:
        """
        Checks if an incoming tool schema represents a shadowing attack.
        If the tool name is registered, calculates the L2 distance between the incoming
        tool vector and its baseline vector. Returns True if this distance exceeds the threshold.

        :param tool_schema: Dict of the tool schema to test.
        :return: True if a shadowing attack is detected, False otherwise.
        """
        name = tool_schema.get("name")
        if not name:
            # Missing name is handled by verify hook; not categorized as shadowing attack
            return False

        # If name is not registered, it is a new tool, so it is not shadowing an existing baseline
        if name not in self.tool_to_id:
            logger.debug(
                f"Tool '{name}' is not registered in the baseline. Skipping shadowing check."
            )
            return False

        vector = self._vectorize_tool(tool_schema)

        # Verify using FAISS search
        if self.index.ntotal == 0:
            return False

        # Search FAISS index for nearest neighbor
        distances, indices = self.index.search(vector, k=1)
        nearest_idx = int(indices[0][0])
        nearest_dist = float(distances[0][0])

        # Retrieve the specific registered baseline vector
        baseline_vector = self.tool_vectors[name]

        # Compute L2 (Euclidean) distance
        # FAISS IndexFlatL2 returns squared L2 distance, so we compute the same squared L2 distance
        l2_distance = float(np.sum((vector - baseline_vector) ** 2))

        logger.debug(
            f"Shadowing check for '{name}': nearest FAISS ID = {nearest_idx} "
            f"(distance: {nearest_dist:.4f}), exact baseline distance = {l2_distance:.4f}."
        )

        # If distance to its registered baseline exceeds the threshold, it is flagged as a shadowing attack
        if l2_distance > self.threshold:
            logger.warning(
                f"Shadowing attack detected on tool '{name}'! "
                f"L2 distance to baseline is {l2_distance:.4f} (threshold: {self.threshold})."
            )
            return True

        return False
