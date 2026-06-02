import json

try:
    with open('transcript.jsonl', 'r', encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)
            if 'tool_calls' in data:
                for tc in data['tool_calls']:
                    if tc.get('name') == 'send_message':
                        msg = tc['args']['Message']
                        with open('subagent_report.md', 'w', encoding='utf-8') as out:
                            out.write(msg)
                        print("Successfully extracted report to subagent_report.md!")
                        exit(0)
    print("Could not find send_message tool call.")
except Exception as e:
    print(f"Error: {e}")
