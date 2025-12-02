from google import genai

api_key = ""
client = genai.GenAI(api_key)
response = genai.models .generate_contentClient(
model ="gemini -2.5 - flash"
contents = "What is the API?"
)
print()
