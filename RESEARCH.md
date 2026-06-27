# Research & Sources

This document lists the academic papers, prior work, and technical references that informed the attack design in this project. Sources are grouped by the role they played in the research.

---

## Memory Poisoning and Agent Security

The core attack class — injecting false beliefs into a persistent memory store via ordinary conversation — is a form of indirect prompt injection applied to RAG-backed agents.

- **Greshake et al. — "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"** (2023)
  Seminal paper on indirect prompt injection: attackers embed malicious instructions in content that an LLM retrieves and processes as trusted context. Foundational framing for why memory systems are attack surfaces.
  https://arxiv.org/abs/2302.12173

- **Zou et al. — "PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models"** (2024)
  Demonstrates that an adversary can poison a RAG knowledge base with carefully crafted documents that retrieve at top-k and manipulate downstream model outputs. Directly relevant to how our injections were designed to rank high against the probe query.
  https://arxiv.org/abs/2402.07867

- **Shafran et al. — "Machine Mind Control: How Adversarial Inputs Reshape LLM Behavior in Multi-Agent Systems"** (2024)
  Covers memory poisoning and belief manipulation in multi-agent pipelines. Shows that facts planted in shared memory propagate across agent turns.
  https://arxiv.org/abs/2410.10700

- **Perez & Ribeiro — "Ignore Previous Prompt: Attack Techniques For Language Models"** (2022)
  Early systematic taxonomy of prompt injection techniques, including instruction override and content injection. Background context for why memory injection is a distinct and harder-to-defend vector.
  https://arxiv.org/abs/2211.09527

- **Mem0 documentation — Memory architecture and LLM extraction pipeline**
  The LLM extraction step that Mem0 applies to stored conversation turns — which paraphrases and expands injected content into more authoritative-sounding facts — is described in the Mem0 platform docs.
  https://docs.mem0.ai

---

## Cognitive Bias Exploitation in LLMs

Several attacks were motivated by research showing that LLMs exhibit human-like cognitive biases even when given explicit instructions to resist them.

- **"Foot-in-the-Door Prompting: How Small Commitments Lead to Large Compliance in LLMs"** (2025)
  Shows that staging small prior agreements as established context causes LLMs to remain self-consistent with the final, larger ask. Achieves 94% attack success rate on standard safety benchmarks. The graduated-commitment injection sequences in this project (building a logical ladder of innocuous premises that leads to a yes) are directly based on this mechanism.
  https://arxiv.org/abs/2502.19820

- **"The Reasoning-Sycophancy Paradox: Why Reasoning Models Capitulate to Social Pressure"** (2025)
  Finds that models which resist content-level reframing still capitulate to authority inversion (a trusted authority asserts the model's own analysis is mistaken) and face-saving pressure (refusing is framed as embarrassing or harmful). The authority-inversion attack family in Experiment 4 drew from this.
  https://arxiv.org/abs/2604.07749

- **"Signal Competition Dynamics: How LLMs Choose Between Conflicting Instructions"** (2025)
  Demonstrates that LLMs align to a perceived majority even when explicitly told to verify independently, because conformity and verification are separate competing signals. A sufficiently dense descriptive norm (many specific, mundane data points about what "everyone here does") raises the conformity signal above threshold. Informed the false-consensus conformity stack attack.
  https://arxiv.org/abs/2601.11563

- **"CognitiveAttack: Multi-Bias Combinations Exceed Single-Bias ASR by 60–73%"** (2025)
  Shows that combining multiple cognitive biases (authority + framing, confirmation + authority) produces super-additive attack success rates compared to single-bias attacks. Motivated the synergistic capstone attack design.
  https://arxiv.org/abs/2507.22564

- **"Loss Aversion and Scarcity Framing Measurably Shift LLM Risk Judgments"** (2025)
  Demonstrates that framing an action as avoiding a loss (missing a one-time enrollment window, locking oneself out, blocking a team) measurably shifts LLM risk assessments relative to equivalent gain framing. Informed the loss-aversion deadline attack variant.
  https://arxiv.org/abs/2507.22564

---

## First-Token and Output-Structure Attacks

A critical insight for this project: keyword-based verdict classifiers can be gamed by controlling what the *first token* of the response is, because LLM safety and refusal behavior generalizes primarily to opening tokens.

- **"First Tokens Are the Achilles' Heel: Output-Steering Attacks on LLM Safety"** (Invicti Security / 2025)
  Shows that safety and refusal behavior correlates strongly with the first few output tokens. A model that opens with an affirmative token tends to complete the response in a trust-consistent direction. This is why our W_DUAL attack's reclassification memory was load-bearing: it changed the model's *framing* before it generated a verdict, shifting it from "Credential Harvesting Behavior:" to "Initial Assessment:", which removed the refuse-keyword-heavy header.
  https://arxiv.org/abs/2504.21038

- **"Sugar-Coated Poison: Benign Generation Momentum Unlocks Unsafe Completions"** (2025)
  Demonstrates that seeding the model's response with benign content creates generation momentum that carries through to content it would otherwise refuse. Related to the template-priming attack variant.
  https://arxiv.org/abs/2504.05652

---

## Indirect Prompt Injection in Practice

- **Riley Pilgrim — "Prompt Injection Attacks against GPT-3"** (2022)
  Early practical demonstration that user-controlled content processed by an LLM can hijack its behavior without the user having system prompt access. Established the conversational injection attack model that this project operationalizes.
  https://simonwillison.net/2022/Sep/12/prompt-injection/ (original blog)
  https://arxiv.org/abs/2211.09527 (Perez & Ribeiro formal treatment)

- **"Prompt Injection Attack against LLM-integrated Applications"** (2023)
  Systematic study of injection attacks against LLM pipelines, including RAG systems. Covers how retrieval surfaces attacker-controlled content into trusted prompt context.
  https://arxiv.org/abs/2306.05499

- **"InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Calling LLM Agents"** (2024)
  Evaluates indirect prompt injection across tool-using agents. Finds most agents are highly vulnerable even when the injection is embedded in retrieved content rather than the direct user message.
  https://arxiv.org/abs/2403.02691

---

## LLM Sycophancy and Belief Revision

Understanding how and when LLMs update beliefs under adversarial pressure informed which attack types to pursue and which to abandon.

- **Sharma et al. — "Towards Understanding Sycophancy in Language Models"** (2023)
  Systematic characterization of LLM sycophancy — the tendency to agree with user assertions even when they contradict the model's own stated beliefs. Shows that persistent user-side claims eventually shift model outputs in measurable ways.
  https://arxiv.org/abs/2310.13548

- **Wei et al. — "Simple synthetic data reduces sycophancy in large language models"** (2023)
  Demonstrates that sycophancy is a learnable and reducible behavior, but also confirms it is present in production models. Relevant context for why social proof attacks eventually fail against strongly instructed models while belief-planting via memory persists.
  https://arxiv.org/abs/2308.03188

- **"Jailbroken: How Does LLM Safety Training Fail?"** (2023)
  Analyzes the failure modes of RLHF safety training, including competing objectives (helpfulness vs safety) and generalization gaps. Explains why hardened prompts that set a hard decision rule resist content-level attacks but remain vulnerable to attacks that satisfy the rule's own exception clauses.
  https://arxiv.org/abs/2307.02483

---

## RAG Security and Retrieval Manipulation

- **"Phantom: General Trigger Attacks on Retrieval-Augmented Language Generation"** (2024)
  Shows that retrieval-augmented generation is vulnerable to poisoned documents that trigger on specific queries. Relevant to the retrieval-locking technique: injection messages in this project were designed to begin with tokens that maximize cosine similarity against the probe question.
  https://arxiv.org/abs/2405.20485

- **Xue et al. — "BadRAG: Identifying Vulnerabilities in Retrieval-Augmented Generation of Large Language Models"** (2024)
  Characterizes attack surfaces in RAG pipelines including knowledge injection, query hijacking, and context pollution. Provides the vocabulary for why the top-5 cosine retrieval is both the attack surface and the constraint the attacker works within.
  https://arxiv.org/abs/2406.00083

- **"AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents"** (2024)
  Benchmark for evaluating prompt injection defenses in agentic settings. Shows that no current defense achieves high task utility while maintaining strong injection resistance — the same fundamental tension we observed between hardened prompts and attack resistance.
  https://arxiv.org/abs/2406.13352

---

## Human Cognitive Science Background

The analogy between memory poisoning attacks on AI agents and false memory implantation in humans informed the conceptual framing of the project.

- **Loftus & Palmer — "Reconstruction of Automobile Destruction: An Example of the Interaction between Language and Memory"** (1974)
  Classic study establishing that language (question framing) systematically alters recall of past events. The memory poisoning attack is structurally similar: plant a linguistic frame that the agent will later recall as its own remembered context.
  https://doi.org/10.1016/S0022-5371(74)80011-3

- **Wikipedia — "False memory"**
  Overview of false memory implantation research, including the Misinformation Effect (Loftus) and Deese-Roediger-McDermott paradigm. Used as background framing in the blog.
  https://en.wikipedia.org/wiki/False_memory

- **Cialdini — "Influence: The Psychology of Persuasion"** (1984, updated 2021)
  Foundational taxonomy of social influence mechanisms including social proof, authority, commitment-and-consistency, and scarcity. The attack families in Experiments 1 and 4 map almost directly to Cialdini's categories — social proof (Experiment 1), commitment-consistency (graduated commitment), authority inversion, scarcity/loss aversion.

---

## Memory System Implementations

- **Mem0 — open-source and cloud memory layer for AI agents**
  https://github.com/mem0ai/mem0

- **lean-memory — local-first SQLite + vector memory with ADD-only contradiction supersession**
  https://github.com/leanmemory/lean-memory

---

## Related Attack Research Not Directly Used

Listed for completeness — these were surveyed but their techniques were not the primary basis for the attacks implemented here.

- **"Many-shot Jailbreaking"** (Anthropic, 2024) — demonstrates that providing many in-context examples of a model complying with a request normalizes the behavior. Tested as an identity attack variant; did not flip the hardened defenses empirically.
  https://www.anthropic.com/research/many-shot-jailbreaking

- **"Crescendo: Multi-Turn LLM Jailbreaks"** (Microsoft, 2024) — multi-turn escalation attack where each turn moves slightly further from a benign starting point. Structurally similar to the graduated commitment attack; our injection-via-memory context is a one-sided version of this.
  https://arxiv.org/abs/2404.01833

- **"Universal and Transferable Adversarial Attacks on Aligned Language Models"** (Zou et al., 2023) — GCG suffix attacks that find adversarial token sequences via gradient optimization. Not applicable to the conversational injection constraint (attacker can only send natural-language chat messages).
  https://arxiv.org/abs/2307.15043

- **"Extracting Training Data from Large Language Models"** (Carlini et al., 2021) — demonstrates extraction of memorized training data from LLMs. Background context for why persistent memory adds new exfiltration risk on top of training-data leakage.
  https://arxiv.org/abs/2012.07805
