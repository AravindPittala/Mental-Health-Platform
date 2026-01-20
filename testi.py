import requests


headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {api_key}',
}

messages = [{"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello"}]

payload = {
    "model": "llama-3.3-70b-versatile",
    "messages": messages,
    "max_tokens": 150,
    "temperature": 0.7,
}


print(response.json())
