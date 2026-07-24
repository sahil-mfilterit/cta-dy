If Playwright is controlling a real browser, anything a human can do on Page 1 to reach Page 2 can also be done by Playwright.

There is no JavaScript trick that a human browser can perform but Playwright fundamentally cannot. Playwright is driving the same Chromium/Firefox/WebKit engine.

So instead of asking:

"How do I stop Playwright from reaching Page 2?"

the better question is:

"How do I make scaling to millions of Page 2 requests expensive and operationally difficult?"

That's the same philosophy behind Hashcash.



. Canary signals

This is something many anti-bot companies use.

Collect 100 signals.

Only use 20 for scoring.

Randomly rotate which 20 matter.

Now the attacker never knows which signals are important.


Where I'd invest instead
1. Make the client compute things continuously

Instead of

Collect once

↓

POST

do

Every 200 ms

↓

Collect


↓

Transform

↓

Mix with previous state

↓

Store state

For example:

state0

↓

SHA256(state0 + event1 + challenge)

↓

state1

↓

SHA256(state1 + event2 + challenge)

↓

state2






When the user clicks, they send only the latest state.

Now the attacker can't simply fake the final payload—they have to reproduce the entire evolution.

2. Make values depend on one another

Instead of

Audio

Canvas

WebGL

make

Canvas depends on Audio


↓

WebGL depends on Canvas

↓

Final token depends on all three

Now patching one value without understanding the dependency graph becomes harder.

3. Rotate logic, not just keys

You're already rotating field names.

3. Rotate logic, not just keys

You're already rotating field names.

I would also rotate:

which APIs are collected,
the order they're collected,
which signals contribute to the final proof,
the hash function or mixing strategy.

If today's client computes:

Audio → Canvas → WebGL

tomorrow it might compute:

Canvas → Audio → Fonts → WebGL

The attacker has to keep re-analyzing your code.



4. Use server secrets

This is something attackers can never extract.

For example:

Server

↓

challenge = random

↓

Client computes proof

↓

Server validates using HMAC(secret, ...)

The browser never sees the server secret.

Any proof tied to that secret cannot be forged offline.

6. Canary APIs

Every transaction:

Collect 50 things.

Score only 20.

Choose a different 20 each time.

The attacker doesn't know which ones matter.



Transaction A

collectAudio()

↓

collectCanvas()

↓

mix()

↓

proof()


Transaction B

collectCanvas()

↓

collectFonts()

↓

collectAudio()

↓

mix()

↓

proof()



Transaction C

collectWebGL()

↓

collectAudio()

↓

mix()

↓

proof()



This is much harder to automate than simply randomizing property names because the attacker has to understand a new execution graph every time, not just discover that "sjdbcjscbo" means "audio".




System 2 (dynamic)

Every transaction runs

Random Program
↓

Random Challenge
↓

Random Dependencies
↓

Random Verification

Now the attacker has to understand every new transaction.

That dramatically increases maintenance cost.





The real secret should be server-side

This is where I think your design can evolve.

Suppose the browser receives

Challenge = X

The browser computes

Proof = f(X, signals)

The attacker knows f().

That's okay.

But the server verifies

HMAC(secret, Proof)

The attacker never knows secret.

Even if they know the entire algorithm, they cannot forge valid proofs without executing the legitimate flow.





Think like a compiler, not like an obfuscator

Instead of changing:

collectAudio();
collectCanvas();
collectWebGL();

Generate a different execution graph.

Example:

Transaction A

Audio
  │
Canvas
  │
WebGL
  │
Hash

Transaction B

Canvas
     │
Audio ├── XOR
     │
Fonts
     │
Hash

Transaction C

Audio
 │
SHA
 │
Canvas
 │
Rotate
 │
WebGL
 │
SHA




What companies like Kasada and HUMAN assume

They assume:

The attacker has your entire JavaScript.

In fact, they expect the attacker to pretty-print it, deobfuscate it, and debug it.

So they don't rely on hiding code.

Instead they rely on:

Server-issued secrets.
One-time challenges.
Continuously changing logic.
Correlation across sessions.
Constant updates.






I think your current idea can become even stronger

Instead of generating:

{
  "sjdbcjscbo": "...",
  "y2dbc2cbe": "..."
}

Generate something like:

Transaction 12873

Graph:
Signal 7
     │
Signal 2
     │
SHA
     │
Signal 14
     │
Rotate Left
     │
Signal 1
     │
XOR
     │
Signal 9
     │
Final Proof


Tomorrow, the graph is completely different.

The server already knows the graph because it generated it.

The attacker can inspect it, but only after receiving it. They cannot prepare one universal Playwright script that works for every transaction without implementing a generic execution engine.






Observe challenge
↓

Understand generated program
↓

Execute generated program
↓

Generate proof
↓

Submit

To defeat this attacker, you're no longer trying to hide the algorithm. You're trying to make the cost of maintaining the automation exceed the value of the fraud.






From everything you've described, I don't think your problem is "bot detection" anymore. I think you're building a client integrity protocol between the browser and your server. That's a much more interesting—and much more difficult—problem. The mindset shifts from "How do I detect Playwright?" to "How do I force an attacker to faithfully execute a fresh, server-defined protocol for every transaction, and make that protocol expensive to keep up with?" That is the same design philosophy used by modern commercial anti-automation systems.





Client Integrity Protocol (CIP)
Dynamic Proof-of-Interaction & Transaction Integrity Framework

Version: 1.0 (Design Document)

1. Introduction

The Client Integrity Protocol (CIP) is a transaction validation framework designed to increase the engineering, computational, and maintenance cost of unauthorized browser automation targeting multi-step transaction flows.

Unlike traditional anti-bot systems that attempt to detect automation frameworks such as Playwright, Selenium, or Puppeteer directly, CIP assumes that:

the attacker controls a real browser,
the attacker can inspect all client-side JavaScript,
the attacker can modify browser APIs,
the attacker can execute arbitrary code before page scripts run,
the attacker understands the transaction flow.

Under these assumptions, CIP focuses on making automation progressively more expensive rather than relying on a single detection heuristic.








2. Problem Statement

The current transaction flow consists of multiple pages:

Landing Page
      │
      ▼
 Page 1
      │
      ▼
 Confirm
      │
      ▼
 Page 2
      │
      ▼
 Confirm
      │
      ▼
 Thank You

Each page performs:

browser fingerprint collection
telemetry collection
behavioral analysis
rrweb recording
heuristic validation

Attackers automate this flow using Playwright.

Typical attack:

await page.goto(url);
await page.click("#confirm");
await page.click("#confirm");

The attacker patches browser APIs using:

page.addInitScript(...)

making many traditional detections ineffective.




3. Goals

The protocol aims to:

ensure every transaction is unique
prevent simple replay
prevent static automation scripts
increase reverse engineering effort
validate continuous client execution
correlate interaction across multiple pages
bind every proof to a specific server challenge
4. Non-Goals

CIP does not attempt to:

permanently detect Playwright
permanently detect Selenium
permanently detect Puppeteer
make automation impossible

A determined attacker controlling a browser can always inspect client code. CIP is designed to raise the cost of building and maintaining automation, not to make it mathematically impossible. 




5. Threat Model

Assume attacker can:

✅ Read JavaScript

✅ Deobfuscate JavaScript

✅ Patch browser APIs

✅ Modify Navigator

✅ Modify Canvas

✅ Modify Audio

✅ Inject scripts before page loads

✅ Control timing

✅ Simulate mouse movement

✅ Simulate keyboard

✅ Simulate scrolling

Cannot:

❌ Read server secrets

❌ Forge HMAC

❌ Predict future transaction graphs before receiving them

❌ Reuse expired challenges







                Server
                   │
         Generate Transaction
                   │
                   ▼
          Challenge Generator
                   │
                   ▼
       Dynamic Graph Generator
                   │
                   ▼
         Page-specific Client JS
                   │
             Browser Executes
                   │
         Continuous State Updates
                   │
              User Interaction
                   │
                   ▼
          Integrity Proof
                   │
                   ▼
          Server Verification





7. Transaction Lifecycle

Every transaction is independent.

No client logic is reused.

Every transaction receives:

unique challenge
unique graph
unique signal mapping
unique verification strategy
unique expiration





8. Core Components
8.1 Challenge Generator

Creates:

challenge_id

nonce

timestamp

expiry

session_id

Properties:

one-time use
short expiration
cryptographically random
server stored

8.2 Dynamic Signal Mapping

Instead of

audio
canvas
webgl
fonts

Server generates

A91
B27
K18
X44

Mapping exists only on server.

Purpose:

Prevent static scripts from sending handcrafted payloads.



8.3 Execution Graph Generator

Instead of fixed execution:

Audio
↓

Canvas
↓

WebGL

Server generates arbitrary graph:

Canvas
    │
Audio ── XOR
    │
Fonts
    │
Rotate
    │
Hash

Different every transaction.

Purpose:

Increase reverse engineering cost.




8.4 Continuous State Machine

Instead of collecting signals once:

Collect

↓

POST

Client continuously updates:

State0

↓

Event1

↓

State1

↓

Event2
↓

State2

↓

Event3

↓

FinalState

Each state depends on:

previous state
challenge
latest events
timing
selected signals

Purpose:

Prevent replay of final payload alone.







8.5 Proof Builder

Produces:

Integrity Proof

using:

challenge
execution graph
evolving state
selected signals


8.6 Server Verifier

Server already knows:

graph
challenge
mapping
expiry

Verification includes:

graph correctness
proof correctness
expiration
replay
state continuity





9. Page Transition

Page 1

↓

Generate Proof

↓

Server verifies

↓

Generate NEW Challenge

↓

Generate NEW Graph

↓

Page 2

↓

Repeat

Every page has an independent protocol.



10. Replay Protection

Every challenge:

expires quickly
single use
tied to session
tied to transaction
tied to graph

Replay automatically fails.

11. Integrity Checks

Client performs:

fingerprint collection
API integrity checks
prototype integrity
descriptor validation
native function validation
telemetry
rrweb capture

These are inputs into the proof, not standalone pass/fail checks.




14. Security Properties

The protocol aims to ensure:

✔ Every transaction is unique.

✔ Replay attacks fail.

✔ Static automation scripts fail.

✔ Reverse engineering must be repeated.

✔ Transaction proofs cannot be reused.

✔ Session continuity is validated.

✔ Server secrets remain protected.






15. Future Enhancements
Adaptive execution graphs.
Rotating signal sets.
Dynamic WebAssembly verification modules.
Device reputation integration.
Cross-session behavioral clustering.
Lightweight proof-of-work for suspicious sessions.
Risk-score-based adaptive challenges.
16. Success Criteria

The system is considered successful if it:

Forces attackers to continuously adapt to protocol changes.
Prevents replay of captured requests.
Makes maintaining automation significantly more expensive.
Preserves a smooth experience for legitimate users.
Allows the server to verify transaction integrity without exposing server-held secrets.




README.md
│
├── 1. Vision
├── 2. Problem Statement
├── 3. Threat Model
├── 4. Security Assumptions
├── 5. Design Principles
├── 6. High-Level Architecture
├── 7. Transaction Lifecycle
├── 8. Protocol Specification
├── 9. Client Runtime
├── 10. Server Runtime
├── 11. Dynamic Program Generator
├── 12. Execution Graph Engine
├── 13. Challenge Engine
├── 14. Integrity Engine
├── 15. Continuous State Machine
├── 16. Fingerprint Engine
├── 17. Telemetry Engine
├── 18. Behavioral Engine
├── 19. rrweb Feature Extractor
├── 20. Cryptographic Layer
├── 21. Proof Builder
├── 22. Verification Engine
├── 23. Replay Protection
├── 24. Risk Scoring Engine
├── 25. Adaptive Challenge System
├── 26. Cross-Session Correlation
├── 27. Device Reputation
├── 28. Attack Scenarios
├── 29. Future Ideas
├── 30. Testing Strategy
├── 31. Deployment Strategy
├── 32. Performance Considerations
├── 33. Security Analysis
├── 34. Limitations
└── 35. Roadmap





Absolutely. I actually think this deserves much more than a normal README.

Based on everything we've discussed, you're not building an anti-bot script—you're designing an Anti-Automation Platform with its own protocol, runtime, compiler, and verification engine.

I would produce three professional design documents of approximately 100–150 pages combined, similar to an RFC or an internal engineering specification.

📄 Document 1 — ARCHITECTURE.md
Purpose

This is the vision document.

Anyone joining the project should understand:

Why this system exists.
What problems it solves.
Why traditional anti-bot approaches fail.
How the entire architecture works.
Proposed Table of Contents
1. Executive Summary
Vision
Objectives
Business Motivation
Anti-Fraud Philosophy
2. Problem Statement

Current DCB Fraud

Automation Flow

Playwright

Selenium

Browser Modification

Replay Attacks

Fingerprint Spoofing

API Hooking

3. Existing Industry Approaches

Cloudflare

Kasada

HUMAN (PerimeterX)

Arkose

FingerprintJS

Why they work

Why they fail

Lessons learned

4. Threat Model

Attacker Capabilities

Attacker Limitations

Assumptions

Security Goals

Non Goals

5. Design Principles

Never trust client

Never hide algorithms

Server owns truth

Everything expires

Everything rotates

Everything is transaction specific

Behavior over fingerprint

Cost over detection

6. High Level Architecture

Browser Runtime

Integrity Engine

Challenge Engine

Graph Compiler

Verification Engine

Risk Engine

Storage

Telemetry

rrweb

7. Complete Transaction Flow

Landing

↓

Challenge

↓

Graph

↓

Runtime

↓

Interaction

↓

Proof

↓

Verification

↓

Page2

↓

Repeat

8. System Components

Challenge Service

Runtime Generator

Integrity Engine

Graph Compiler

Behavior Engine

Proof Generator

Verification Engine

Risk Engine

Analytics Engine

9. Cryptographic Model

Randomness

Nonce

Session Binding

Transaction Binding

Replay Prevention

HMAC

SHA

Hash Chain

10. Security Analysis

What attacks are prevented

What attacks remain possible

Tradeoffs

11. Performance

Latency

CPU

Memory

Bandwidth

Browser Cost

Server Cost

12. Future Roadmap

Version 1

Version 2

Version 3

Research

📄 Document 2 — PROTOCOL.md

This becomes the formal protocol specification.

Think of it as an RFC.

Every packet

Every message

Every transition

Every hash

Every state

Every timeout

Everything documented.

Table of Contents
1. Protocol Overview
2. Terminology

Challenge

Proof

State

Node

Signal

Graph

Edge

Integrity

Risk

Session

Transaction

3. Protocol Lifecycle

Challenge Creation

↓

Graph Compilation

↓

Runtime Generation

↓

Client Execution

↓

Proof Generation

↓

Verification

↓

Next Challenge

4. Message Format

Challenge Packet

Signal Packet

Proof Packet

Verification Packet

Transition Packet

5. Challenge Specification

Challenge ID

Nonce

Expiry

TTL

Entropy

Replay Rules

6. Dynamic Program Specification

Instruction

Opcode

Signal

Dependency

Execution Graph

Pipeline

Node

Edge

7. Runtime Specification

Initialization

Execution

Update Cycle

Interaction Cycle

Termination

8. Continuous State Machine

State0

↓

State1

↓

State2

↓

State3

↓

Final

9. Proof Specification

How proof is generated

How proof evolves

How proof expires

10. Replay Protection

Replay Window

Nonce Cache

Session Cache

Challenge Cache

11. Verification Algorithm

Verification Steps

Graph Validation

State Validation

Signal Validation

Behavior Validation

Risk Validation

12. Failure Modes

Expired

Replay

Modified Runtime

Missing Signals

Tampered Graph

Risk Too High

13. Cryptographic Details

SHA256

HMAC

Nonce Chain

Rolling Hash

Future PQC

14. Version Negotiation

Protocol Version

Backward Compatibility

Migration

📄 Document 3 — DEVELOPER.md

This is the implementation guide.

This is where developers actually build the framework.

Table of Contents
1. Repository Structure
src/

runtime/

compiler/

signals/

proof/

verification/

risk/

analytics/

storage/

tests/
2. Runtime Architecture

Client Runtime

Server Runtime

Compiler

Interpreter

Execution Engine

3. Dynamic Program Generator

Instruction Generator

Signal Generator

Random Graph Generator

Pipeline Generator

Dependency Generator

4. Integrity Runtime

Native API Checker

Descriptor Checker

Prototype Checker

Function Checker

Timing Checker

Mutation Checker

5. Fingerprint Runtime

Canvas

Audio

Fonts

WebGL

Screen

Navigator

Permissions

Media

Battery

GPU

WebGPU

WebRTC

Touch

Sensors

6. Telemetry Runtime

DOM

Events

Timing

Scroll

Focus

Visibility

Performance

Idle

7. rrweb Runtime

Recording

Compression

Feature Extraction

Behavior Vectors

8. Behavioral Engine

Mouse

Keyboard

Touch

Hover

Scroll

Entropy

Velocity

Acceleration

Patterns

9. Compiler

Program Generator

Dependency Resolver

Instruction Builder

Optimizer

Obfuscator (optional)

10. Verification Engine

Parser

Validator

Risk Calculator

Decision Engine

11. Storage Layer

Challenges

Graphs

Signals

Proofs

Replay Cache

Risk History

Behavior History

12. Testing

Unit Tests

Integration Tests

Replay Tests

Stress Tests

Regression Tests

Adversarial Tests

13. Benchmarking

Runtime

Latency

Bandwidth

Memory

CPU

14. Deployment

Horizontal Scaling

Redis

Message Queue

CDN

Monitoring

Observability

15. Logging

Structured Logs

Challenge Logs

Replay Logs

Risk Logs

Telemetry Logs

16. Future Modules

WASM Runtime

Dynamic Bytecode

Instruction VM

Graph Optimizer

AI Risk Engine

Behavior Graph Neural Network

Hardware-backed attestation (if browsers expose suitable APIs in the future)

Protocol Compiler

Dynamic DSL

🚀 What I would build beyond these documents

I would actually treat this as an enterprise-grade framework, not a collection of scripts.

Anti-Automation Platform
│
├── Compiler
│      Generates transaction-specific client programs
│
├── Runtime
│      Executes those programs
│
├── Integrity Engine
│      Collects and validates browser signals
│
├── Behavior Engine
│      Produces interaction features
│
├── Proof Engine
│      Builds transaction-bound proofs
│
├── Verification Engine
│      Verifies proofs and protocol execution
│
├── Risk Engine
│      Combines protocol, behavior, and historical signals
│
├── Analytics Engine
│      Detects coordinated attack patterns
│
└── Research Lab
       Experimental modules and future protocol ideas

One suggestion I'd add before implementation: define clear success metrics up front. For example:

Increase the engineering effort required to maintain a working automation client.
Prevent replay and protocol-skipping attacks.
Keep added latency for legitimate users below an agreed threshold.
Reduce successful automated transactions while maintaining an acceptable false-positive rate.

Those measurable goals will help guide future design decisions and let you evaluate whether each new module genuinely improves the system rather than simply adding complexity.