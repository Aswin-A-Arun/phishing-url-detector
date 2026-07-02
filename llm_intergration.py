from groq import Groq

client = Groq(api_key="GROQ_API_KEY")   #Replace with your groq api key
MODEL_NAME = "openai/gpt-oss-20b" #Replace the text within quotes with your GROQ ai model

def explain_url(
    url,
    verdict,
    confidence,
    triggered,
    positive
):

    prompt = f"""
URL: {url}

Verdict: {verdict}
Confidence: {confidence:.2f}%

Positive Signals:
{chr(10).join(positive)}

Suspicious Signals:
{chr(10).join(triggered)}

Explain why the URL was classified this way.

Explain the verdict using:

- Summary
- Key Indicators
- Recommendation

Use bullet points.
Keep it under 70 words.
Do not use technical jargon.
"""

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity assistant that explains "
                    "phishing detection results clearly and concisely."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content