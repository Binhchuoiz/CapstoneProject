#tham khao: src:https://www.youtube.com/watch?v=q5HiD5PNuck
#get api key: api platform: https://platform.openai.com/usage
import openai
import os


openai.api_key = os.getenv("OPENAI_API_KEY")


def ask_openai(message):
	response = openai.ChatCompletion.create(
		model="gpt-3.5-turbo",
		messages=[
			{"role": "system", "content": "You are an helpful assistant."},
			{"role": "user", "content": message},
			# {"role": "user", "content": prompt}
		]
	)

	answer = response.choices[0].message.content.strip()
	return answer


#test bot in prompt
# if __name__ == '__main__':
#     while True:
#           user_input = input("You: ")
#           if user_input.lower() in ["quit", "exit", "bye"]:
#                 break
          
#           response = ask_openai(user_input)
#           print("Chatbot: ", response)


#PATH: E:\FPT University\Major SS9\IAP491\Web\CapstoneProject\CVEAlert\CVEAlert