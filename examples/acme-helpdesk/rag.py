"""Help-article search. Staff and customers can upload articles and attachments."""
import chromadb

store = chromadb.PersistentClient(path="./vectors").get_or_create_collection("help")


def add_document(doc_id, text, uploaded_by):
    store.add(ids=[doc_id], documents=[text], metadatas=[{"uploaded_by": uploaded_by}])


def search_help_articles(question, k=5):
    hits = store.query(query_texts=[question], n_results=k)
    return "\n---\n".join(hits["documents"][0])
