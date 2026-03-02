import requests, base64

invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
stream = False

headers = {
    "Authorization": "Bearer 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",
    "Accept": "text/event-stream" if stream else "application/json"
}

payload = {
    "model": "moonshotai/kimi-k2.5",
    "messages": [{"role": "user", "content": "hello"}],
    "max_tokens": 16384,
    "temperature": 1.00,
    "top_p": 1.00,
    "stream": stream,

}

response = requests.post(invoke_url, headers=headers, json=payload)

if stream:
    for line in response.iter_lines():
        if line:
            print(line.decode("utf-8"))
else:
    print(response.json())
