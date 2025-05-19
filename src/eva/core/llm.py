import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI


load_dotenv()

def get_llm() -> ChatOpenAI:
    from eva import app_state

    return ChatOpenAI(
        model=app_state["model"],
        temperature=app_state["temp"],
        api_key=os.getenv("PLAYGROUND_API_KEY"),
        base_url=os.getenv("PLAYGROUND_URL")
    )
