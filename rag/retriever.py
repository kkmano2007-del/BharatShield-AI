import json
import os

from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

KNOWLEDGE_BASE_PATH = os.path.join(
    BASE_DIR,
    "knowledge_base",
    "scam_examples.json"
)


class ScamRetriever:

    def __init__(self):

        self.model = SentenceTransformer(
            "all-MiniLM-L6-v2"
        )

        with open(
            KNOWLEDGE_BASE_PATH,
            "r",
            encoding="utf-8"
        ) as file:

            self.documents = json.load(file)

        self.messages = [
            item["message"]
            for item in self.documents
        ]

        self.document_embeddings = self.model.encode(
            self.messages
        )


    def retrieve(
        self,
        query,
        top_k=3
    ):

        query_embedding = self.model.encode(
            [query]
        )

        similarities = cosine_similarity(
            query_embedding,
            self.document_embeddings
        )[0]

        ranked_indices = similarities.argsort()[::-1]

        results = []

        for index in ranked_indices[:top_k]:

            item = self.documents[index].copy()

            item["similarity"] = round(
                float(similarities[index]),
                3
            )

            results.append(item)

        return results
