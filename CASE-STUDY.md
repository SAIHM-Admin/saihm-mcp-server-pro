# Case study: a quarter of regulated work with three agent roles, SAIHM + SHM

Every capability named here is one SAIHM or SHM documents publicly. The company is fictional. The staffing
comparison is a worked scenario, and each removed role is matched to the capability that replaces it. SHM works with
a paid SAIHM plan, and each agent identity that runs SHM needs one.

## The short version

- **About twenty agents become three roles.** Memory carries the context, so you stop adding agents to hold it.
- **Every turn costs less.** SHM brings forward only what the task needs, within a budget you set, and finds it on your
  own machine without spending model tokens.
- **The savings outgrow the subscription.** In the worked month below, the team saves about $37,700 in model tokens and
  supervision time. Set that against your plan on the pricing page.
- **Nothing to rip out.** Keep your AI tools and your way of working. SAIHM works with the tools your team already uses,
  and you can start free.

## The quarter

A regulated payments company runs 40 services, each in its own repository. In one quarter its engineering team must:

1. **Migrate** card settlement to a new ledger service across all 40 repositories, keeping every interface decision consistent.
2. **Handle a production incident** in week 6, mid-migration, and deliver a postmortem a regulator can follow.
3. **Honour a customer's erasure request** that touches memories several agents hold.
4. **Give a partner bank's planning agent** time-boxed access to the delivery forecast, and end it on the contract date.
5. **Check every release** against the team's rules, in CI, without a person reading each changelog.

## A common way to staff it today: about 20 agents

```
                      +-------------+
                      | Coordinator |  passes context between the others
                      +------+------+
                             |
  +------------+-------------+-------------+----------------+
  |            |             |             |                |
 Service x8  Handoff x2   Retrieval x1   Incident x2     Deletion x3
                                         (commander,
                                          scribe)

  + Partner liaison x1   + Compliance and audit x1   + CI rules x1

  Total: 20 agents
```

Why so many? Each agent's context window holds one slice of the 40 repositories, every session starts cold, and
copies of what agents learn pile up in places that each need their own clean-up. Agents are added to carry context,
so the count tracks the context limits instead of the work.

## With SAIHM + SHM: three roles

```
   +----------+      +----------+      +----------+
   | Lead     |      | Builder  |      | Guard    |
   | plans,   |      | parallel |      | reviews, |
   | decides, |      | changes  |      | CI and   |
   | partners |      | 40 repos |      | erasure  |
   +----------+      +----------+      +----------+
         |                 |                 |
         +----- scoped, expiring shares -----+
                           |
+--------------------------+--------------------------+
| SHM beside each agent: ranks memory by meaning and  |
| keyword, brings forward what the task needs within  |
| your budget, and records why each one was chosen    |
+-----------------------------------------------------+
| SAIHM: memory encrypted on your machine before it   |
| leaves it, portable across AI tools and machines,   |
| and erasure that is final                           |
+-----------------------------------------------------+
```

When the migration needs throughput, run the Builder as several parallel instances. They share one memory, so they
need no coordinator, no handoff agents and no retrieval agent.

| Roles the usual build needs | What lets three roles do the same work |
|---|---|
| 8 service agents | SHM brings forward only the memories the current task needs, within a budget you set per turn, so a Builder's context stays clean across all 40 repositories and the tasks stay apart. Host hooks bring the relevant memories into each coding session as it starts, with no prompt, and one ranking can federate each repository's notes with SAIHM. |
| Coordinator and 2 handoff agents | SAIHM memory persists across sessions, tools and machines. SHM's warm start resumes its own state in a new session or on another device. Agents pass each other exactly the memories they need through scoped shares, and SHM follows share states to stay in step. |
| Retrieval agent | SHM's hybrid ranking, with an optional reranker on your own machine, runs beside each agent and puts the relevant memories in front of it as the work begins, before it asks. |
| Incident commander and scribe | The Lead saves each decision as it is made, naming the memories it drew on, and SHM shows why each of those was brought forward. The postmortem is written from those records. |
| 3 deletion agents | One SAIHM erasure destroys the memory's key, so the stored copy is permanently unreadable. Each computer's local copy drops it at its next recall, a backup of a computer keeps that copy as it was then, and SHM removes the memory from its index, its caches and everything it derived from it. |
| Partner liaison | A read or read-write SAIHM share pinned to the bank agent's identity, with an expiry on the contract date. Revoking it ends access at once; what the bank already read stays with the bank. |
| Compliance and CI rules agents | The team's rules live as SAIHM memories. The Guard recalls them in every review and every CI run, and a correction is saved once and recalled in every later review. In CI, a resident SHM service keeps the index warm, so each job asks a running service instead of rebuilding it. |

## What it saves

Token economy comes from six places:

- **No cold starts.** Memory persists across sessions, tools and machines, and SHM's warm start resumes its own state, so
  no agent re-reads the same files, wiki pages and tickets each morning.
- **Small, steady context.** SHM's per-turn budget caps what it brings forward, so long sessions stay lean.
- **Ranking without model tokens.** SHM's embedder and reranker run on your machine, so finding the right memory costs
  no model tokens.
- **No coordination traffic.** Shared memory replaces the handoff summaries and status messages agents send each other.
- **Lists without reads.** SAIHM lists your memories without reading their content, free on every plan.
- **Fewer agents.** Each agent you retire also retires the instructions, tools and context it loads on every turn.

A worked month (replace every number with yours):

| | Usual build | SAIHM + SHM |
|---|---|---|
| Agents running | 20 | 5 (Lead, 3 Builders, Guard) |
| Working turns a day, same work | 3,000 | 3,000 |
| Extra coordination turns a day | 600 | 0 |
| Context carried per turn | 80k tokens | 30k tokens |
| Input tokens a day | 288M | 90M |
| People supervising the agents | 2 | 0.5 |

Over 21 working days that is about 4.2 billion input tokens saved, about $12,500 at an example rate of $3 per million
tokens before caching discounts, plus about $25,200 of supervision time at $100 an hour: about $37,700 a month. Your
provider's caching discounts change both columns.

## One task, start to finish

```
 Builder opens repo 23 --> SHM ranks the team's memories --> the few relevant ones arrive, each with its reason
        |
        v
 change made, decision saved to SAIHM and shared with the Lead and the Guard --> share states --> their SHM picks it up
```

## One erasure, followed through SAIHM and SHM

```
 request --> Guard finds the memories --> you confirm --> SAIHM destroys each memory's key
                                                              |
      erasure feed --> each agent's SHM drops the memory and everything it derived
      each computer's local copy drops it at its next recall
```

## The prompts that run the quarter (adapt the names and rules)

**Lead**
- Recall my SAIHM decision records for the ledger migration and plan this week's work across the 40 repositories, with owners and open questions.
- Remember in SAIHM as a decision record: settlement events carry an idempotency key, decided today by Dana, revisit if duplicates exceed 0.1%.
- Share my SAIHM memory "Q4 delivery forecast" with the bank's planning agent in ./identities/bank-planner.json, read-only, until 31 December.

**Builder**
- Recall what SAIHM holds about repository 23 and the migration's interface decisions, then apply the settlement change and save what you changed and why.
- Before you stop, save this session's state to SAIHM so I can resume it tomorrow from another machine or AI tool.

**Guard**
- In this CI job, recall the team's SAIHM memory "release rules" and fail the job if the changelog breaks any of them.
- A customer asked us to erase their data. Find every SAIHM memory that mentions them, show me each one, and erase them after I confirm.
- Recall the SAIHM decision records the incident drew on and draft the postmortem timeline from them.

For CI, start the SAIHM MCP server once before the job (its first start after an install takes longer), and let SHM's
local models download once, or provide them, where the network blocks downloads.

## Check it on your own work

Pick one real task. Give SAIHM and SHM a day on your project so the memories exist, then run the task in a fresh
session twice, once with your current setup and once with SAIHM and SHM, and compare the token counts your AI tool
reports. The difference repeats in every session, for every agent, every day.

## Why teams switch

- **It pays for itself.** Fewer agents, leaner turns and no coordination traffic cut the model bill and the hours spent
  watching agents. The memory carries the context, so the agent count follows the work.
- **Clean context.** Each agent spends its tokens on the task in front of it.
- **One memory everywhere.** It follows your key across AI tools and machines.
- **Private by design.** Memories are encrypted on your machine before they leave it, SHM runs on your side with its models on your own machine, and its index is encrypted at rest under a key your team holds.
- **Erasure you can stand behind.** A destroyed key is final, and SHM forgets everything it derived.
- **Sharing that ends on time.** Every grant is scoped, pinned to one identity, and can carry an expiry.
- **Nothing to rip out.** It works with the AI tools your team already uses, and you can start free.

## Make it yours

Keep the three roles, add Builder instances when you need throughput, and swap in your repositories, rules, partners and deadlines. Start with the Lead's first prompt;
SHM does the ranking from the first session.
