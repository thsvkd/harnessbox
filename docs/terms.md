# Terms notes per harness

Not legal advice. This page records what was read at the cited pages, and when; it says "not found" where nothing was found. Read the
current pages yourself before you let other people log in to a runner you operate. The design rule that keeps every option open is
the same for all harnesses: the unmodified CLI runs in the user's own box, the user logs in with their own account through the CLI's
own login, and the operator never collects, stores or brokers the credential (it stays in the user's home on the runner; the host
app sees only the login URL, a device code, or the one-time code the user pastes back, which is bound to that CLI process by PKCE).

## Claude Code (Anthropic)

Read 2026-10-16: <https://code.claude.com/docs/en/legal-and-compliance>. Hosting unmodified Claude Code where each user signs in
with their own Claude subscription is a use the page describes, under these conditions:

- the operator accepts Anthropic's **Commercial Terms of Service**;
- the binary is not modified and its built-in authentication is not bypassed;
- the operator does not pay for, resell or broker usage on the users' behalf;
- each user authenticates with their own credentials, which the operator does not collect, store or broker;
- the login completes in Anthropic's own flow;
- Pro and Max limits assume ordinary, individual usage.

Grey area: in the paste-code flow the one-time code passes through the host app on its way to the CLI's stdin. It is useless
outside that CLI process (PKCE), but it does pass. Do not log it (harnessbox does not).

## Codex (OpenAI)

Read 2026-10-16 (research for review-automation): no official page was found that covers a third party hosting Codex where each user
signs in with their own ChatGPT plan. What the official docs do say:

- "Don't expose Codex execution in untrusted or public environments";
- automation should use API keys;
- "Treat ~/.codex/auth.json like a password";
- device-code login must be allowed by the user or their workspace admin in ChatGPT's security settings.

The account-sharing clause of OpenAI's terms could only be seen quoted by third parties (the official page returned 403). Treat
Codex as needing legal review or OpenAI's confirmation before you open it to other people; review-automation keeps it behind a
switch that is off by default.

## Grok (xAI)

Read 2026-10-16:

- Consumer Terms of Service (<https://x.ai/legal/terms-of-service>, last updated 2026-10-12): "You may not share your account
  credentials or make your account available to anyone else, and are responsible for all activities that occur under your account."
  Also: "If you create an account or use the Service on behalf of another person or entity, you must have the authority to accept
  these Terms on their behalf."
- Acceptable Use Policy (<https://x.ai/legal/acceptable-use-policy>, effective 2026-08-14) forbids "Take unauthorized actions on
  behalf of others" and circumventing safeguards.
- **Not found:** any xAI statement that explicitly allows or forbids a third party hosting the Grok CLI for subscription users, or a
  CLI-specific automation clause.

Each user logging in to their own account in their own box fits the credential clause as long as nobody else uses that account.
Get xAI's or counsel's confirmation before opening it to other people.

## Candidates not shipped

- **Gemini CLI** (checked 0.64.0): Google's Code Assist FAQ
  (<https://developers.google.com/gemini-code-assist/resources/faqs>, updated 2026-10-09) says personal "Login with Google" stopped
  serving the individual, Google AI Pro and Ultra tiers on 2026-06-18, Gemini CLI included. <https://geminicli.com/docs/resources/tos-privacy/>
  calls direct Code Assist access with third-party software using Gemini CLI's OAuth a violation; running the real CLI is not that, and
  nothing found addresses hosting it for other users.
- **opencode** (checked 1.19.0): a client, so the provider's terms apply. GitHub says it officially supports Copilot Pro, Pro+,
  Business and Enterprise in OpenCode through the device login
  (<https://github.blog/changelog/2026-01-16-github-copilot-now-supports-opencode/>); opencode's own docs say Anthropic prohibits
  using Claude Pro/Max subscriptions through it (<https://opencode.ai/docs/providers/>).
