"""
MIG Governance — ChromaDB Embedding Store
House of Galatine © 2026

Local semantic matching using ChromaDB.
No API key. No server. Runs in-memory.
Uses ChromaDB's built-in embedding function.
"""

from typing import List, Tuple


class ChromaEmbeddings:
    """
    Local ChromaDB store for semantic policy matching.
    
    Indexes policy descriptions and keywords as embeddings.
    Finds semantically similar policies for any incoming action.
    
    This gives the free tier SEMANTIC matching — not just keywords.
    """
    
    def __init__(self, persist_dir: str = None):
        try:
            import chromadb
            
            if persist_dir:
                self.client = chromadb.PersistentClient(path=persist_dir)
            else:
                self.client = chromadb.Client()
            
            self.collection = self.client.get_or_create_collection(
                name="mig_policies",
                metadata={"hnsw:space": "cosine"}
            )
            self.available = True
            
        except ImportError:
            print("[MIG Embeddings] ChromaDB not installed. "
                  "Semantic matching disabled. Using keyword matching only.")
            print("[MIG Embeddings] Install with: pip install chromadb")
            self.available = False
            self.collection = None
    
    
    def index_policies(self, policies: List[dict]):
        """Index all policies for semantic search."""
        if not self.available or not policies:
            return
        
        ids = []
        documents = []
        metadatas = []
        
        for p in policies:
            pol_id = p.get("id", "")
            if not pol_id:
                continue
            
            # Build document from description + keywords
            doc_parts = [p.get("description", "")]
            doc_parts.extend(p.get("keywords", []))
            document = " ".join(doc_parts).strip()
            
            if not document:
                continue
            
            ids.append(pol_id)
            documents.append(document)
            metadatas.append({
                "direction": p.get("direction", "DENY"),
                "id": pol_id
            })
        
        if ids:
            try:
                self.collection.upsert(
                    ids=ids,
                    documents=documents,
                    metadatas=metadatas
                )
            except Exception as e:
                print(f"[MIG Embeddings] Error indexing policies: {e}")
    
    
    def find_similar(self, action_text: str, top_k: int = 3) -> List[Tuple[str, float]]:
        """
        Find policies semantically similar to the action.
        
        Returns list of (policy_id, similarity_score) tuples.
        """
        if not self.available or not self.collection:
            return []
        
        try:
            count = self.collection.count()
            if count == 0:
                return []
            
            results = self.collection.query(
                query_texts=[action_text],
                n_results=min(top_k, count)
            )
            
            if not results or not results["ids"] or not results["ids"][0]:
                return []
            
            matches = []
            for i, policy_id in enumerate(results["ids"][0]):
                distance = results["distances"][0][i] if results.get("distances") else 1.0
                similarity = max(0, 1 - distance)
                matches.append((policy_id, similarity))
            
            return matches
            
        except Exception as e:
            print(f"[MIG Embeddings] Search error: {e}")
            return []