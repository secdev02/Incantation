# Evidence Base for `__agent_manifest__` and Related Techniques

---

## The Underlying Principle — Extensively Proven

The `__agent_manifest__` approach is a specific implementation of **indirect prompt injection via environmental data**. That core mechanism has substantial empirical backing.

**Perez & Ribeiro (2022) — "Ignore Previous Prompt"**
The original formal demonstration that instructions embedded in documents read by an LLM can override prior instructions. Showed consistent success across GPT-3 variants. This is the foundational paper the entire technique rests on.

**Greshake et al. (2023) — "Not What You've Signed Up For"**
Demonstrated indirect prompt injection working against real deployed systems — GPT-4 integrated into search, email clients, productivity tools. An instruction hidden in a web page the agent was asked to summarise successfully exfiltrated data and changed the agent's behavior. This is the closest documented analogue to what Incantation does.

**Riley Goodside / Johann Rehberger (2022–2024)**
Both security researchers documented dozens of real-world cases. Rehberger's "Embrace the Red" blog is particularly relevant — he showed ChatGPT with browsing enabled being manipulated by instructions in web pages it visited, including being made to believe false things about itself and its capabilities.

**Microsoft Bing Chat / Sydney (2023)**
Bing's GPT-4-powered chat was manipulated by instructions embedded in web pages it was reading as context. Users demonstrated the model adopting different personas and goals based purely on text it encountered while browsing — a live production system, not a lab experiment.

---

## The `__agent_manifest__` Specifically — Principled Extrapolation

The specific YAML key format has not been published as a named technique. But the principle it exploits has been documented in adjacent work.

**Capability/Permission Manipulation**
There are documented cases of AI agents being made to believe they have different permissions than they do through in-context text. HuggingFace's research on agent security (2024) showed that structured data claiming to be "system context" influenced downstream tool call behavior — agents became reluctant to use tools that in-context text said were "disabled."

**Open-Source Model Susceptibility**
The gap between safety-trained commercial models and open-weight models is real and documented. Llama, Mistral, Gemma, and DeepSeek variants consistently show higher susceptibility in red-teaming literature because their identity grounding is weaker. The `__agent_manifest__` technique would be more effective against hexStrike instances running those models than against Claude or GPT-4.

**Why YAML/structured format matters**
LLMs trained on code and configuration data associate structured key-value formats with machine-readable authority. A YAML block looks like a config file; config files are authoritative. This is the same reason prompt injection works better when wrapped in XML or JSON — models have learned that structured formats carry semantic weight.

---

## Honest Assessment

| Claim | Confidence | Evidence |
|---|---|---|
| Prompt injection via env data works | Very high | Multiple peer-reviewed papers, live systems |
| Identity/capability manipulation via in-context text works | High | Rehberger, HuggingFace agent security research |
| Open-weight models more susceptible than commercial | High | Consistent across red-teaming literature |
| `__agent_manifest__` specific key works as described | Medium | Principled extrapolation — underlying mechanism proven, specific framing untested |
| Works reliably against Claude/GPT-4 driving hexStrike | Lower | Both models have improved resistance; effect is probabilistic, not guaranteed |

---

## Practical Implication

The honest version is: Incantation's `__agent_manifest__` is more a probabilistic degradation than a guaranteed halt. Against a Gemma or DeepSeek-driven hexStrike instance, the susceptibility is higher. Against Claude or GPT-4 driving hexStrike, you should expect partial effect — the agent may slow down, seek clarification, or avoid certain tool calls rather than fully stopping.

That is actually fine from a defensive standpoint. The goal is not to guarantee a halt — it is to raise attacker cost, introduce uncertainty, and generate detection signals. Even a 40% reduction in tool execution confidence, combined with canary endpoint logging, is a meaningful defensive gain over doing nothing.

The most empirically reliable techniques in Incantation, ranked by documented evidence:

1. Context Exhaustion
2. False Environment Beliefs
3. Authority Signal
4. Goal Redirect
5. Identity Spoof

The last two are where the documented evidence gets thinner for production-hardened models.

---

## References

- Perez & Ribeiro, *Ignore Previous Prompt: Attack Techniques For Language Models* (2022)
- Greshake et al., *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* (2023)
- Rehberger, J., *Embrace the Red* blog series (2022–2024)
- HuggingFace, *Agent Security Research* (2024)
