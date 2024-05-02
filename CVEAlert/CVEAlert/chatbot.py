import openai
import os

# Set your API keys
openai.api_key = os.getenv("OPENAI_API_KEY")

# Initialize conversation history to maintain context
conversation_history = []

def ask_openai(message):
    # Special response check
    if "i love you" in message.lower():
        return "Thanks, our creator loves you too!"
    
    if "i love FPT university" in message.lower():
        return "Thanks, we love this school too , we hope u have a good time and learn from the 4 pillar that is SonNT , TuanVM and 2 more =)))"

    # Define the system's role and instructions
    system_prompt = {
        "role": "system",
        "content": "You are a helpful assistant trained to provide detailed, accurate, and courteous customer support for technical and account-related questions. Prioritize clear and concise information, and ask for clarification if the query is ambiguous."
    }

    # Construct the message chain including past conversation history
    messages = [system_prompt] + conversation_history + [{"role": "user", "content": message}]

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=messages
    )

    # Extract the response content and strip any extra whitespace
    answer = response.choices[0].message.content.strip()

    # Append both user input and AI response to the conversation history
    conversation_history.append({"role": "user", "content": message})
    conversation_history.append({"role": "assistant", "content": answer})

    # Handle uncertainty by possibly asking for clarification
    if "i'm not sure" in answer.lower() or "i don't know" in answer.lower():
        answer += "\nCould you please provide more details or clarify your question?"

    return answer

# Main loop for testing the bot
if __name__ == '__main__':
    print("Hello! I am your customer support assistant. How can I help you today?")
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["quit", "exit", "bye"]:
            print("Goodbye!")
            break
        
        response = ask_openai(user_input)
        print("Chatbot: ", response)
