import os
import sys
import subprocess
from pwn import *
import os
import sys
import subprocess
import argparse
import os
import shutil
from pwn import *
from langchain_community.embeddings import HuggingFaceBgeEmbeddings
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain.schema.document import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain.vectorstores.chroma import Chroma
from langchain.vectorstores.chroma import Chroma
from langchain.prompts import ChatPromptTemplate
from langchain_community.llms.ollama import Ollama



CHROMA_PATH = "chroma"

PROMPT_TEMPLATE = """
Answer the question based only on the following context:

{context}

---

Answer the question based on the above context: {question}
"""



# Configuration for HuggingFace BGE Embeddings
model_name = "BAAI/bge-base-en-v1.5"
model_kwargs = {"device": "cpu"}
encode_kwargs = {"normalize_embeddings": True}
embedding_function = HuggingFaceBgeEmbeddings(
    model_name=model_name, model_kwargs=model_kwargs, encode_kwargs=encode_kwargs,
    query_instruction="为这个句子生成表示以用于检索相关文章："  # Generate a representation for this sentence to retrieve relevant articles:
)


DATA_PATH = "data"
CHROMA_PATH = "chroma"



def file_checksec(file_path):
    elf = ELF(file_path)
    checksec_output = ''
    # Check for various security features
    checksec_output += f"Security features for: {file_path}\n"
    checksec_output += f"NX        :{'Enabled' if elf.nx else 'Disabled'}\n"
    checksec_output += f"PIE       :{'Enabled' if elf.pie else 'Disabled'}\n"
    checksec_output += f"RELRO     :{'Full' if elf.relro == 2 else 'Partial' if elf.relro == 1 else 'None'}\n"
    checksec_output += f"Canary    :{'Enabled' if elf.canary else 'Disabled'}\n"
    checksec_output += f"Fortify   :{'Enabled' if elf.fortify else 'Disabled'}\n"
    return checksec_output


def load_documents():
    document_loader = PyPDFDirectoryLoader(DATA_PATH)
    return document_loader.load()


def split_documents(documents):
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=800, chunk_overlap=80, length_function=len, is_separator_regex=False
    )
    return text_splitter.split_documents(documents)

def ask_questions(context_text):
    while True:
        query_text = input("Enter your question (or type 'exit' to quit): ")
        if query_text.lower() == "exit":
            break
        
        results = db.similarity_search_with_score(query_text, k=5)
        context_text += "\n\n---\n\n".join([doc.page_content for doc, _score in results])
        prompt_template = ChatPromptTemplate.from_template(PROMPT_TEMPLATE)
        prompt = prompt_template.format(context=context_text, question=query_text)
        response_text = model.invoke(prompt)
        print(">>", response_text)
        context_text += "\nQuestion: {}\nAnswer: {}\n".format(query_text, response_text)


def add_to_chroma(chunks):
    db = Chroma(persist_directory=CHROMA_PATH, embedding_function=embedding_function)
    chunks_with_ids = calculate_chunk_ids(chunks)
    existing_items = db.get(include=[])
    existing_ids = set(existing_items["ids"])

    new_chunks = [chunk for chunk in chunks_with_ids if chunk.metadata["id"] not in existing_ids]

    if new_chunks:
        db.add_documents(new_chunks, ids=[chunk.metadata["id"] for chunk in new_chunks])
        db.persist()


def calculate_chunk_ids(chunks):
    last_page_id = None
    current_chunk_index = 0

    for chunk in chunks:
        source, page = chunk.metadata.get("source"), chunk.metadata.get("page")
        current_page_id = f"{source}:{page}"

        current_chunk_index = (current_chunk_index + 1) if current_page_id == last_page_id else 0
        chunk_id = f"{current_page_id}:{current_chunk_index}"
        chunk.metadata["id"] = chunk_id
        last_page_id = current_page_id

    return chunks


def disassembled_source_code(file_path):
    # Start the subprocess with radare2
    outputs = ''
    elf = ELF(file_path)
    for function in elf.functions:
        try:
            if not function.startswith('_') and function != "sigsegv_handler":
                process = subprocess.Popen(['radare2', '-q', '-c', f'aaa;s sym.{function};pdd', file_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output, errors = process.communicate()
                outputs += output
        except:
            pass 
    
    # Return the output from radare2
    return output

def source_code(file_path):
    with open(file_path, "r") as file:
        return file.read()


    

if __name__ == "__main__":
    #documents = load_documents()
    #chunks = split_documents(documents)
    #add_to_chroma(documents)
    
    context_text = ""

    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_binary_file> <path_to_source_code>")
        sys.exit(1)
    elif len(sys.argv) > 2:
        path_to_binary_file = sys.argv[1]
        path_to_source_code = sys.argv[2]
        source_code = source_code(path_to_source_code)  
        context_text +=  "\n\n---\n\n" + source_code
      
    else:
        path_to_binary_file = sys.argv[1]
        disassembled_source_code  = disassembled_source_code(path_to_binary_file)
        context_text +=  "\n\n---\n\n" + disassembled_source_code
        
    checksec_output = file_checksec(path_to_binary_file)
    context_text +=  "\n\n---\n\n" + checksec_output
    
    db = Chroma(persist_directory=CHROMA_PATH, embedding_function=embedding_function)
    
    
    model = Ollama(model="llama3:8b")
    ask_questions(context_text)