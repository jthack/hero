# Hero

This project is a proof of concept for a Hackbot, an AI-driven system that autonomously finds vulnerabilities in web applications. It takes a raw HTTP request as input and attempts to identify and exploit potential security vulnerabilities. It's probably not the best way to build a hackbot, but you can view it as inspiration.

## Getting Started

### Prerequisites

- Python 3.8 or later
- `openai` Python package
- `requests` Python package

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jthack/hero.git
   ```
2. Navigate to the project directory:
   ```bash
   cd hero
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To use the Hackbot POC, you need to provide a raw HTTP request as input. The system will then generate ideas for potential vulnerabilities, modify the requests to test these ideas, and validate the results.

1. Prepare a file containing a raw HTTP request (e.g., `request.txt`).
2. Run the Hackbot script, passing the request file as input:
   ```bash
   cat request.txt | python hackbot.py
   ```

The output will include details of the ideas generated, the modified requests, and the validation results.
