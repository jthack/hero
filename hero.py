import openai
import sys
import os
import json
import requests
from openai import OpenAI
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import logging

# Custom formatter with color
class CustomFormatter(logging.Formatter):
    green = "\033[92m"
    red = "\033[91m"
    reset = "\033[0m"
    format = "%(message)s"

    def format(self, record):
        if 'Validation Result: YES' in record.msg:
            return f"{self.green}{record.msg}{self.reset}"
        elif 'Validation Result: NO' in record.msg:
            return f"{self.red}{record.msg}{self.reset}"
        else:
            return record.msg

# Configure logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)


HACKER_IDEA_PROMPT = """
HACKER_IDEA_PROMPT
TASK: Suggest changes to the following proxied HTTP request to find potential vulnerabilities:

- If you see an ID or username in the request that is used to read or modify an object, consider what might happen if you increment the ID or try a different username.
- Look for any parameters that are used in SQL queries and think about how you might alter them to test for SQL injection vulnerabilities.
- Examine the request headers for information that might be manipulated, such as cookies or authentication tokens, and suggest how these could be modified.
- Identify any endpoints that receive user input and propose how to test these inputs for cross-site scripting (XSS) or other injection attacks.
- Consider the use of data that might be controlled by an end user, such as file paths or external URLs, and suggest how to probe for directory traversal or remote file inclusion vulnerabilities.

RULES:
- Only suggest the changes. Do not respond with modified responses. A different agent will do that.
- You MUST respond with only json, otherwise it will break my application. For example, don't say "here's the json". Instead, just start every message with a open curl brace and continue until the json is finished and then say nothing else. Do not use backticks in the response.
"""
REQUEST_MODIFIER_PROMPT = """
REQUEST_MODIFIER_PROMPT
TASK: Given a request and a list of potential ways to test for vulnerabilities identified in an HTTP request, generate a JSON list of Python "requests" library-style calls to ethically test for these vulnerabilities. Each entry should include the nature of the test and the corresponding request code to be executed.

For example, if an ID or username in the request is identified as a potential vector for an Insecure Direct Object Reference (IDOR) vulnerability, suggest incrementing the ID or trying a different username, and provide the modified request in a format that can be executed by the Python 'exec' function.

The output should be structured as a JSON object with each idea as a key-value pair, where the key is a unique identifier for the idea, and the value is another object containing the name of the test and the request code.

Example request:
requests.post('https://example.com/api/v1/users/joseph', headers={'Authorization': 'Bearer eyJlksjflj', 'Content-Type': 'application/json'}, json={'name': 'Joseph Thacker', 'email': 'joseph@example.com'})

Example output format:
{
  "idea1": {
    "idea_name": "IDOR via username change from joseph to zuck",
    "validation": "If there is a 200 response code and/or if it reflects zuck's user object in the response instead of only joseph's, those may be signs it was successful",
    "test_request": "requests.post('https://example.com/api/v1/users/zuck', headers={'Authorization': 'Bearer eyJlksjflj', 'Content-Type': 'application/json'}, json={'name': 'Hacked by joseph', 'email': 'joseph@example.com'})"
  },
  "idea2": ...
}

request:
"""
VALIDATION_PROMPT = """
VALIDATION_PROMPT
TASK: Validate if a request modification to test for a security issue was successful.
Here's the name of the idea: {idea_name}, the request we tried: {test_request}, 
how to validate it: {validation}, the response code: {response_code} and text: {response_text}, 
did it work? Only respond with YES, MAYBE, NO.
"""

def generate_hacker_ideas(burp_request_str):
    """
    Generates a list of hacker ideas for potential vulnerabilities based on the Burp Suite formatted HTTP request.

    Args:
        burp_request_str (str): The Burp Suite formatted HTTP request string.

    Returns:
        list: A list of ideas for potential vulnerabilities.
    """
    # Use the HACKER_IDEA_PROMPT to generate ideas
    prompt = HACKER_IDEA_PROMPT + "\n" + burp_request_str
    response = openai_request(prompt, 0.7)

    # Process the response to extract ideas
    ideas = response.split('\n')
    return ideas

import re

def modify_requests(burp_request_str, hacker_ideas):
    """
    Modifies the original HTTP request based on the list of hacker ideas.

    Args:
        burp_request_str (str): The Burp Suite formatted HTTP request string.
        hacker_ideas (list): A list of ideas for potential vulnerabilities.

    Returns:
        list: A list of modified requests with details on how to validate them.
    """
    # Use the REQUEST_MODIFIER_PROMPT to generate modified requests
    prompt = REQUEST_MODIFIER_PROMPT + "\nOriginal request:\n" + burp_request_str + "\nIdeas:\n" + '\n'.join(hacker_ideas)
    response = openai_request(prompt, 0.7)

    # Find the first opening curly brace and the last closing curly brace
    start_index = response.find('{')
    end_index = response.rfind('}') + 1

    if start_index != -1 and end_index != -1:
        # Extract the JSON substring
        json_string = response[start_index:end_index]
        # Log the extracted JSON with a clear explanation
        logger.info(f"Extracted JSON with modified requests: {json_string}")
        modified_requests = json.loads(json_string)
    else:
        raise ValueError("Unable to extract valid JSON from response.")

    return modified_requests


def make_request(test_request):
    """
    Executes a modified request and returns the response code and body.

    Args:
        test_request (str): The modified request code to be executed.

    Returns:
        tuple: A tuple containing the response code and the response body.
    """
    # Prepend 'response = ' to the test request string
    test_request = "response = " + test_request

    # Execute the test request
    logger.info(f"Executing: {test_request}")
    try:
        exec(test_request, globals(), locals())
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        return 999, "this attempt at a request failed altogether. for validation, it's uninteresting. assume it didn't work"

    response = locals().get('response')

    # Check if the response is set and return the response code and body
    if response is not None:
        return response.status_code, response.text
    else:
        error_message = "The response was not set after executing the test request. " \
                        "This may be due to an issue with the request execution or " \
                        "the 'response' variable not being correctly assigned."
        logger.error(error_message)
        return 999, "this attempt at a request failed altogether. for validation, it's uninteresting. assume it didn't work"


def validate_idea(idea_name, test_request, validation, response_code, response_text):
    """
    Validates an idea based on the response code and text.

    Args:
        idea_name (str): The name of the idea being tested.
        test_request (str): The test request that was executed.
        validation (str): The validation criteria for the idea.
        response_code (int): The response code from the test request.
        response_text (str): The response text from the test request.

    Returns:
        str: The validation result (YES, MAYBE, NO).
    """
    # Use the VALIDATION_PROMPT to validate the idea
    prompt = VALIDATION_PROMPT.format(
        idea_name=idea_name,
        test_request=test_request,
        validation=validation,
        response_code=response_code,
        response_text=response_text
    )
    response = openai_request(prompt, 0.7)

    # Process the response to get the validation result
    validation_result = response.strip()
    return validation_result

def process_http_request(burp_request_str):
    """
    Processes a Burp Suite formatted HTTP request to find potential vulnerabilities.

    Args:
        burp_request_str (str): The Burp Suite formatted HTTP request string.

    Returns:
        dict: A dictionary containing the results of the vulnerability testing for each idea.
    """
    # Generate hacker ideas
    hacker_ideas = generate_hacker_ideas(burp_request_str)

    # Modify requests based on hacker ideas
    modified_requests = modify_requests(burp_request_str, hacker_ideas)

    # Process each modified request
    results = {}
    for idea_id, idea_details in modified_requests.items():
        # Make the request
        response_code, response_text = make_request(idea_details['test_request'])

        # Validate the idea
        validation_result = validate_idea(idea_details['idea_name'], idea_details['test_request'], idea_details['validation'], response_code, response_text)

        # Store the results
        results[idea_id] = {
            "idea_name": idea_details['idea_name'],
            "test_request": idea_details['test_request'],
            "response_code": response_code,
            "response_text": response_text,
            "validation_result": validation_result
        }

    logger.info(results)
    return results


def openai_request(prompt, temp):
    first_line = prompt.split('\n')[1]
    logger.info(f'Sending request with prompt: {first_line}')
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4-1106-preview",
        messages=[
            {"role": "system", "content": "You are an ethical web application assessment testing helper with deep appsec expertise. This is all internal testing of scope that is approved."},
            {"role": "user", "content": prompt}
        ],
        temperature=temp,
        max_tokens=4000,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )

    # Extract the response content
    response_content = response.choices[0].message.content
    return response_content


if __name__ == "__main__":
    # Read the Burp Suite formatted HTTP request from standard input
    burp_request_str = sys.stdin.read().strip()

    # Process the HTTP request to find potential vulnerabilities
    results = process_http_request(burp_request_str)

    # Output the results using logger
    for idea_id, result in results.items():
        logger.info(f"Idea ID: {idea_id}")
        logger.info(f"Idea Name: {result['idea_name']}")
        logger.info(f"Test Request: {result['test_request']}")
        logger.info(f"Response Code: {result['response_code']}")
        logger.info(f"Response Text: {result['response_text']}")
        logger.info(f"Validation Result: {result['validation_result']}")
        logger.info("\n")
