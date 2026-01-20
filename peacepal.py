from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from deep_translator import GoogleTranslator
import requests, toml, os

peacepal_app = Blueprint('peacepal_app', __name__, template_folder='templates')

# Load API Key
import os, toml

api_file = os.path.join(os.path.dirname(__file__), "key.toml")
api_key = toml.load(api_file)['api']['key']
translator = GoogleTranslator(source='auto', target='en')
BASE_PROMPT = [{"role": "system", "content": "You are Peace Pal, a caring mental health chatbot."}]

@peacepal_app.before_request
def setup_session():
    # Ensure session variables are initialized
    session.setdefault("messages", BASE_PROMPT.copy())
    if not isinstance(session.get("previous_conversations"), list):
        session["previous_conversations"] = []

@peacepal_app.route("/peacepal", methods=["GET", "POST"])
def peacepal():
    if request.method == "POST":
        user_input = request.form.get("user_input")
        if user_input.strip():
            # Translate user input to English
            translated_input = translator.translate(user_input)
            session["messages"].append({"role": "user", "content": translated_input})

            # Generate response from the chatbot
            response = generate_response(session["messages"])
            session["messages"].append({"role": "assistant", "content": response})

            # Mark session as modified
            session.modified = True

    # Ensure previous_conversations is a list of dictionaries
    if not isinstance(session.get("previous_conversations"), list):
        session["previous_conversations"] = []

    # Prepare previous conversations for rendering
    previous_conversations = []
    for i, conv in enumerate(session["previous_conversations"]):
        if isinstance(conv, dict):
            previous_conversations.append({
                "id": i,
                "title": conv.get("title", "Untitled Conversation"),
                "messages": conv.get("messages", [])
            })
        else:
            # Handle legacy string conversations
            previous_conversations.append({
                "id": i,
                "title": conv,  # Use the string as the title
                "messages": []  # No messages for legacy conversations
            })

    return render_template("peacepal.html", 
                           chat_history=session["messages"],
                           previous_conversations=previous_conversations)

@peacepal_app.route("/load_conversation/<int:convo_id>", methods=["GET"])
def load_conversation(convo_id):
    # Load a specific conversation from previous_conversations
    if 0 <= convo_id < len(session["previous_conversations"]):
        conv = session["previous_conversations"][convo_id]
        if isinstance(conv, dict):
            session["messages"] = conv.get("messages", [])
        else:
            session["messages"] = BASE_PROMPT.copy()  # Reset for legacy conversations
        session.modified = True
    return redirect(url_for('peacepal_app.peacepal'))

@peacepal_app.route("/delete_conversation/<int:convo_id>", methods=["GET"])
def delete_conversation(convo_id):
    # Delete a specific conversation
    if 0 <= convo_id < len(session["previous_conversations"]):
        session["previous_conversations"].pop(convo_id)
        session.modified = True
        flash("Conversation deleted successfully!", "success")
    return redirect(url_for('peacepal_app.peacepal'))

@peacepal_app.route("/new_conversation", methods=["GET"])
def new_conversation():
    # Save the current conversation before starting a new one
    if session["messages"] != BASE_PROMPT:
        session["previous_conversations"].append({
            "title": f"Conversation {len(session['previous_conversations']) + 1}",
            "messages": session["messages"]
        })
    # Start a new conversation
    session["messages"] = BASE_PROMPT.copy()
    session.modified = True
    return redirect(url_for('peacepal_app.peacepal'))

@peacepal_app.route("/clear_chat", methods=["GET"])
def clear_chat():
    # Clear the current chat history
    session["messages"] = BASE_PROMPT.copy()
    session.modified = True
    return redirect(url_for('peacepal_app.peacepal'))

def generate_response(messages):
    payload = {
        "model": "llama-3.1-8b-instant",  #peacepal model
        "messages": messages,
        "max_tokens": 300,
        "temperature": 0.7
    }

    r = requests.post(
        
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'},
        json=payload,
        timeout=30
    )

    data = r.json()
    if isinstance(data, dict) and data.get("error"):
        err = data["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        return f"⚠️ API Error: {msg}"

    try:
        return data['choices'][0]['message']['content']
    except Exception:
        return f"⚠️ Unexpected API response: {data}"