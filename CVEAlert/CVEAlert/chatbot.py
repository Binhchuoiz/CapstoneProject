#src:https://www.youtube.com/watch?v=q5HiD5PNuck
#api platform: https://platform.openai.com/usage
import openai

openai_api_key ="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"
openai.api_key = openai_api_key


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