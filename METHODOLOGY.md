# Methodology: AI-Augmented Development

This project was developed using AI tools as co-developers — primarily Claude (Anthropic) and Grok (xAI) and ChatGPT.

## What I did

I designed the architecture, specified the invariants, chose the mathematical formulations, defined the test scenarios, and decided what constitutes a passing result. Every claim in this repository is something I can derive on paper or verify by running the code myself. The research questions, the framing, and the limitations sections are mine.

## What the AI tools did

Claude and Grok and ChatGPT generated code to my specifications, helped scaffold test harnesses, assisted with boilerplate (CI config, packaging), and served as rapid iteration partners during development. Some branch names (e.g. `claude/...`) reflect Claude Code sessions where code was generated, reviewed, and committed in a single workflow.

## What this means for you

If you're evaluating this work: the ideas and the math are human-directed. The velocity is augmented. I'm transparent about this because I think the interesting question isn't "did you type every character" but "do you understand what every character does and why it's there." I do.

If you find a bug, an incorrect claim, or a test that doesn't verify what it says it verifies — open an issue. That's the real test of understanding, and I welcome it.
