# truthfit

Tailors a resume to a job for ATS parsers and AI screeners. It cannot lie.

The model proposes; deterministic executed checks own the verdict. Every line of the output is traced to a file you gave it — verbatim, or a rephrase that passed a gate built to reject anything new. If one line can't be traced, nothing is written but the report that says which line.

```bash
python3 truthfit.py --resume base.docx --url https://jobs.ashbyhq.com/acme/123 --evidence notes.md
```

## What it does

1. **Reads the job.** Greenhouse, Lever, Ashby and Workday through their public JSON APIs. Eightfold career sites (Netflix, NVIDIA, Microsoft) and most other pages through the JSON-LD the page already carries. Or `--jd-file`.
2. **Reads your sources.** The base resume plus any `--evidence` files: portfolio, notes, old resumes. Those are the only places a line may come from.
3. **Builds the tailored resume** using moves that cannot invent a claim:
   - reorders bullets inside each job by relevance — titles, companies and dates never move
   - reorders skills, posting's matches first
   - adds a posting keyword to Skills only when your files state it in a sentence that isn't negated. "I have never used MongoDB" does not count as MongoDB.
   - adds the posting's spelling of a skill you already claim (`Security Plus` → `Security+`), because keyword search doesn't expand abbreviations
   - pulls verbatim evidence lines aimed at the qualifications that grade weakest
   - adds `Target role: <posting title>` under your name. It names the job you're applying for. It changes no title you held.
4. **Optional AI rewrite.** A model may rephrase a bullet. A deterministic gate rejects any new number (digits or words — `eight` → `eighty` is caught), name, tool, skill, scope word (`led`, `managed`, `architected`), buzzword or dash. Then a second model call acts as a skeptic and rejects anything that claims more than the original. Rejected rewrites keep your words. Your exact-words version is always written next to it.
5. **Grades it like an AI screener.** Each qualification gets meets / partial / gap with the resume line that proves it, and an A–D grade in the shape Workday HiredScore documents. Then a real model screens the finished resume; every quote it cites is checked verbatim against the resume.
6. **Checks how parsers will read it.** Textkernel's published resume-quality codes, a PDF round trip (text layer, garbled glyphs, columns, header/footer, reading order), Word-file traps (tables, text boxes, columns, contact info in headers), and hidden or AI-directed text.
7. **Tells you which engine reads this application** and what that engine documents about itself.

## Default resume and live download counts

```bash
python3 truthfit.py --default --resume base.pdf --downloads packages.json --pdf
```

- `--default` writes the resume tailored to no job: your lines, your order, the same verifier, the same .md / .docx / .txt / .pdf outputs.
- `--downloads packages.json` (`{"pypi": [...], "npm": [...], "descriptions": {...}}`) fetches live counts from pypistats.org (daily totals with mirrors) and api.npmjs.org (daily totals since first publish). It rewrites the resume's `N lifetime downloads across M published packages`, `PyPI (N installs): ...` and `npm (N installs): ...` lines, and replaces any old telemetry appendix with a fresh "Verified Package Telemetry" section: one line per package and the public URL that proves it. Works with `--default` or a tailored run.
- Every URL, total and the exact `jq` command that reproduces it go in `downloads_receipt.json` next to the output. A failed fetch writes nothing, so a stale number never goes out. pypistats keeps 180 days; past that, a count is marked `+` as a floor.

## What it will never do

- Write a skill, number, employer, title or result that isn't in your files.
- Change a job title you held.
- Add hidden text or instructions aimed at an AI screener. It refuses to run on a file that contains them.

## The verdict

`verify()` is the only thing that decides whether a resume gets written. Every non-heading line must be:
- verbatim in one of your files, or
- a rewrite whose original is verbatim and which passes `rewrite_gate()` again, at verify time, or
- a skills line that is a permutation of one of yours, or contains only terms your files state, or
- the target-role line, with exactly the posting's title.

Plus optional `--identity` (your real email and phone must be present) and `--forbidden` (terms that must never appear — private project names, NDA'd clients). The `.docx` is converted back to text and verified the same way.

`tests/` holds those guarantees as executable checks: invented bullets, inflated numbers in digits and words, scope inflation, unsupported skills, negated skills, forbidden terms, AI-directed text, a wrong target title, download counts swapped and the old appendix dropped. 22 tests, no network, no model.

## Engines covered

Each note in the report comes from the vendor's own documentation where it exists.

| Engine | What it documents | Source |
|---|---|---|
| Eightfold (Netflix, NVIDIA, Microsoft) | 0–5 stars; skill, work and job-title relevance vs calibrated "ideal candidates"; career trajectory | [engineering blog](https://eightfold.ai/engineering-blog/ai-powered-talent-matching-the-tech-behind-smarter-and-fairer-hiring/), [NYC LL144 disclosure](https://eightfold.ai/nyc-eightfold-matching-model) |
| Workday / HiredScore | knockout questions; Skills and Languages aren't auto-filled; basic qualifications decide A/B vs C/D | [Workday docs](https://doc.workday.com/admin-guide/en-us/human-capital-management/recruiting/candidates/set-up-prospects-and-candidates/hdc1552497830785.html), [HiredScore grades](https://doc.workday.com/hiredscore/en-us/workday-hiredscore/recruiter-productivity-/reference--candidate-grades.html) |
| Greenhouse | resume-only Talent Matching, 4–6 weighted skills, "Needs manual review" when it can't parse you | [support](https://support.greenhouse.io/hc/en-us/articles/41396009937307-Talent-Matching) |
| Ashby | per-criterion review of resume and long-form answers | [docs](https://docs.ashbyhq.com/ai-assisted-application-review) |
| Textkernel (formerly Sovren) | the parser inside many ATSs; its own list of resume faults | [quality codes](https://developer.textkernel.com/tx-platform/v10/resume-parser/overview/parser-output/) |
| Dice | Candidate Match on skills and past, present and desired titles; employers sort by it | [employer docs](https://www.dice.com/support/employer/jobs/jobs---prioritize-apps-using-candidate-match.html) |
| LinkedIn | Job Match compares profile and resume with the hirer's qualifications | [help](https://www.linkedin.com/help/linkedin/answer/a7120158) |
| Indeed | Smart Fit Score 0–100 from resume plus AI Recruiter answers | [Indeed](https://www.indeed.com/hire/resources/howtohub/what-is-indeed-smart-screening) |
| ZipRecruiter | Great / Good / Fair / Not a Match; title recency and resume length are features | [press release](https://www.businesswire.com/news/home/20210319005398/en) |
| Welcome to the Jungle | ≤5 criteria, resume only | [help](https://help.welcometothejungle.com/en/how-does-automatic-candidate-screening-work-on-welcome-ats-) |
| HireVue | scores transcribed words only | [SHRM](https://www.shrm.org/topics-tools/news/talent-acquisition/hirevue-discontinues-facial-analysis-screening) |
| Lever, iCIMS, Taleo, Oracle, SuccessFactors, Robert Half, staffing agencies | see `ENGINE_NOTES` | — |

Claims I could not trace to a vendor are not in the tool: endorsement multipliers, daily-login boosts, keyword-density "safe zones", automatic penalties for applying to several roles.

## Limits

- **It can't run any vendor's engine.** Workday, Eightfold and the rest are closed. The grade is an approximation of their documented logic, plus a real model doing the screener's job. On one test posting the deterministic grade said D and the model said C. Treat the model's grade as the better estimate.
- **It can't make a weak match strong.** It surfaces what you have. What you don't have is listed as a gap, or as a related real line you can use as a talking point — never written in.
- **The keyword list is hand-built** (274 terms plus pattern matching, plus model extraction when a model is available). It knows tech and security better than other fields.
- **JavaScript-only job pages and pages behind a login don't fetch.** Paste the posting into a file and use `--jd-file`.
- **I haven't measured callbacks.** No claim here about interview rates.

## Requirements

Python 3.10+, standard library only. External tools: `pandoc` (Word in/out), `pdftotext` / `pdfimages` from poppler (PDF), `typst` (only for `--pdf`), and the `claude` CLI for the model steps — skip them all with `--no-ai`.

```bash
brew install pandoc poppler typst
python3 -m unittest discover -s tests
```

## Other modes

```bash
python3 truthfit.py --check-file resume.pdf          # parseability audit, no job needed
python3 truthfit.py --ats-map applications.jsonl     # which engine reads each job link you've tracked
```

## License

PolyForm Noncommercial 1.0.0. Noncommercial use is free. Commercial use needs a license: matrixbuilderops@proton.me. Copyright SignalCore Inc. and Bastion Fold LLC.
