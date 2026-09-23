#!/usr/bin/env python3
"""
Hank Academy: security training quiz for your Claude Code agentic OS.

The scanner (hank_audit.py) finds your weaknesses; the Academy trains you on
them. Duolingo-style: earn XP, climb ranks, keep a daily streak, collect
badges. Your rank + badges render on the audit's HTML Security Report Card.

No dependencies. Python 3.8+. Progress lives in ~/.hank/academy.json
(override the directory with $HANK_HOME).

Usage:
    python3 hank_quiz.py                     # rapid-fire round (10 questions)
    python3 hank_quiz.py -n 5                # shorter round
    python3 hank_quiz.py --daily             # today's daily question(s)
    python3 hank_quiz.py --daily-goal 3      # set questions-per-day (1-5)
    python3 hank_quiz.py --target DIR        # bias questions toward what the
                                             # audit flags in DIR (the loop!)
    python3 hank_quiz.py --stats             # your dashboard
"""

import argparse
import datetime as dt
import json
import os
import random
import sys

# ---------------------------------------------------------------------------
# Styling (matches hank_audit.py)
# ---------------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

CATEGORIES = ("secrets", "injection", "agency", "hooks", "supply-chain", "hygiene")

CATEGORY_LABEL = {
    "secrets": "🔑 SECRETS",
    "injection": "🧬 INJECTION",
    "agency": "🦾 AGENCY",
    "hooks": "🪝 HOOKS",
    "supply-chain": "📦 SUPPLY CHAIN",
    "hygiene": "🧼 HYGIENE",
}

# Audit rule-id prefix → quiz category. Lets --target turn findings into a
# training plan.
RULE_PREFIX_TO_CATEGORY = {
    "SECRET": "secrets",
    "INJ": "injection",
    "AGENCY": "agency",
    "HOOK": "hooks",
    "SUPPLY": "supply-chain",
    "HYGIENE": "hygiene",
}

# XP → rank ladder. Police-academy themed, obviously.
RANKS = [
    (0, "🎓", "Cadet"),
    (100, "👮", "Officer"),
    (250, "🕵️", "Detective"),
    (500, "🚔", "Sergeant"),
    (1000, "⭐", "Lieutenant"),
    (2000, "🎖️", "Captain"),
    (3500, "🛡️", "Chief of Security"),
]

POINTS_PER_DIFFICULTY = 10   # difficulty 1-3 → 10/20/30 XP per correct answer
PERFECT_ROUND_BONUS = 25     # flawless rapid-fire round of 10+
DAILY_COMPLETE_BONUS = 15    # finishing the daily goal
MASTERY_THRESHOLD = 6        # correct answers in a category → specialist badge

BADGES = {
    "first-day":    ("🎓", "First Day", "Completed your first Academy session"),
    "streak-3":     ("🔥", "On a Roll", "3-day daily streak"),
    "streak-7":     ("📅", "Habit Formed", "7-day daily streak"),
    "streak-30":    ("🗓️", "Iron Discipline", "30-day daily streak"),
    "perfect-10":   ("🏆", "Perfect Round", "10/10 in a rapid-fire round"),
    "century":      ("💯", "Century Club", "100 questions answered"),
    "all-rounder":  ("🧭", "All-Rounder", "A correct answer in every category"),
    "m-secrets":      ("🔑", "Keymaster", "Secrets mastery"),
    "m-injection":    ("🧬", "Injection Immune", "Prompt-injection mastery"),
    "m-agency":       ("🦾", "Agency Auditor", "Excessive-agency mastery"),
    "m-hooks":        ("🪝", "Hook Inspector", "Hooks mastery"),
    "m-supply-chain": ("📦", "Chain of Custody", "Supply-chain mastery"),
    "m-hygiene":      ("🧼", "Clean Freak", "Hygiene mastery"),
}

RIGHT_LINES = [
    "Correct. Hank nods approvingly.",
    "Nailed it.",
    "Sharp. Very sharp.",
    "That's the one. Textbook.",
    "Correct: you've clearly read a breach report or two.",
]
WRONG_LINES = [
    "Nope. This is how breaches start.",
    "Incorrect: but better wrong here than in production.",
    "Not quite. Read the explanation, it'll stick.",
    "Wrong answer. Hank has seen this exact mistake in the wild.",
]


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def hank_home() -> str:
    return os.environ.get("HANK_HOME") or os.path.join(os.path.expanduser("~"), ".hank")


def state_path() -> str:
    return os.path.join(hank_home(), "academy.json")


def fresh_state() -> dict:
    return {
        "xp": 0,
        "rank": {"emoji": RANKS[0][1], "name": RANKS[0][2]},
        "streak": 0,
        "best_streak": 0,
        "last_daily": None,
        "daily_goal": 1,
        "answered": {},         # question id -> {"correct": n, "wrong": n}
        "category_stats": {},   # category -> {"asked": n, "correct": n}
        "badges": [],           # [{"id","emoji","name","earned"}]
        "totals": {"asked": 0, "correct": 0},
        "history": [],          # [{"date","mode","asked","correct","xp"}]
    }


def load_state() -> dict:
    path = state_path()
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                state = json.load(f)
            base = fresh_state()
            base.update(state)
            return base
        except (ValueError, OSError):
            pass
    return fresh_state()


def save_state(state: dict):
    os.makedirs(hank_home(), exist_ok=True)
    with open(state_path(), "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def rank_for(xp: int):
    current = RANKS[0]
    nxt = None
    for threshold, emoji, name in RANKS:
        if xp >= threshold:
            current = (threshold, emoji, name)
        elif nxt is None:
            nxt = (threshold, emoji, name)
    return current, nxt


# ---------------------------------------------------------------------------
# Question bank
# ---------------------------------------------------------------------------

def load_questions(path: str = None) -> list:
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "questions.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["questions"]


def audit_weights(target_dir: str) -> dict:
    """Run the scanner against target_dir and weight categories by findings.
    This is the loop: the audit finds your weaknesses, the quiz trains them."""
    try:
        import hank_audit
    except ImportError:
        return {}
    findings = hank_audit.run_audit(os.path.abspath(target_dir))
    weights = {}
    for f in findings:
        prefix = f.rule_id.split("-")[0]
        cat = RULE_PREFIX_TO_CATEGORY.get(prefix)
        if cat:
            weights[cat] = weights.get(cat, 0) + 1
    return weights


def select_questions(bank: list, state: dict, n: int, weights: dict = None,
                     rng: random.Random = None) -> list:
    """Pick n questions. Preference order:
    1. categories the audit flagged (weights): 3x draw chance per finding
    2. unseen questions before repeats
    3. within repeats, questions answered wrong more than right
    """
    rng = rng or random.Random()
    weights = weights or {}
    answered = state.get("answered", {})

    def draw_weight(q):
        w = 1.0
        w *= 1.0 + 2.0 * min(weights.get(q["category"], 0), 3)  # flagged cats up to 7x
        hist = answered.get(q["id"])
        if hist is None:
            w *= 4.0                                             # unseen first
        elif hist.get("wrong", 0) > hist.get("correct", 0):
            w *= 2.0                                             # retrain misses
        return w

    pool = list(bank)
    picked = []
    while pool and len(picked) < n:
        total = sum(draw_weight(q) for q in pool)
        r = rng.uniform(0, total)
        acc = 0.0
        for q in pool:
            acc += draw_weight(q)
            if acc >= r:
                picked.append(q)
                pool.remove(q)
                break
    return picked


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

def today() -> str:
    return dt.date.today().isoformat()


def check_new_badges(state: dict, session: dict) -> list:
    """Award any badges newly earned. Returns the fresh ones."""
    have = {b["id"] for b in state["badges"]}
    fresh = []

    def award(bid):
        if bid in have:
            return
        emoji, name, desc = BADGES[bid]
        badge = {"id": bid, "emoji": emoji, "name": name, "desc": desc, "earned": today()}
        state["badges"].append(badge)
        have.add(bid)
        fresh.append(badge)

    if state["history"]:
        award("first-day")
    if state["streak"] >= 3:
        award("streak-3")
    if state["streak"] >= 7:
        award("streak-7")
    if state["streak"] >= 30:
        award("streak-30")
    if session.get("mode") == "rapid" and session["asked"] >= 10 and session["correct"] == session["asked"]:
        award("perfect-10")
    if state["totals"]["asked"] >= 100:
        award("century")
    cats_correct = {c for c, s in state["category_stats"].items() if s.get("correct", 0) > 0}
    if all(c in cats_correct for c in CATEGORIES):
        award("all-rounder")
    for cat in CATEGORIES:
        if state["category_stats"].get(cat, {}).get("correct", 0) >= MASTERY_THRESHOLD:
            award("m-" + cat)
    return fresh


def ask_question(q: dict, idx: int, total: int, use_color: bool,
                 input_fn=input, rng: random.Random = None) -> bool:
    rng = rng or random.Random()

    def c(text, code):
        return f"{code}{text}{RESET}" if use_color else text

    stars = "★" * q["difficulty"] + "☆" * (3 - q["difficulty"])
    print(f"  {c(f'Q{idx}/{total}', BOLD)} · {CATEGORY_LABEL[q['category']]} · {c(stars, YELLOW)}")
    print(f"  {c(q['q'], BOLD)}")
    print()

    order = list(range(len(q["choices"])))
    rng.shuffle(order)
    letters = "ABCD"
    for i, choice_idx in enumerate(order):
        print(f"    {c(letters[i] + ')', CYAN)} {q['choices'][choice_idx]}")
    print()

    while True:
        try:
            raw = input_fn("  Your answer: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print("\n  Session ended early; progress up to here still counts.")
            raise
        if raw in letters[: len(order)]:
            break
        print(f"  {c('Pick one of ' + '/'.join(letters[:len(order)]), DIM)}")

    chosen = order[letters.index(raw)]
    correct = chosen == q["answer"]
    if correct:
        xp = q["difficulty"] * POINTS_PER_DIFFICULTY
        print(f"  {c('✓ ' + rng.choice(RIGHT_LINES), GREEN)} {c(f'+{xp} XP', BOLD)}")
    else:
        right_letter = letters[order.index(q["answer"])]
        print(f"  {c('✗ ' + rng.choice(WRONG_LINES), RED)}")
        print(f"  {c('The answer was ' + right_letter + ') ' + q['choices'][q['answer']], YELLOW)}")
    print(f"  {c('└ ' + q['explain'], DIM)}")
    print(f"  {c('(' + q['owasp'] + ')', DIM)}")
    print()
    return correct


def record_answer(state: dict, q: dict, correct: bool):
    ans = state["answered"].setdefault(q["id"], {"correct": 0, "wrong": 0})
    ans["correct" if correct else "wrong"] += 1
    cat = state["category_stats"].setdefault(q["category"], {"asked": 0, "correct": 0})
    cat["asked"] += 1
    if correct:
        cat["correct"] += 1
    state["totals"]["asked"] += 1
    if correct:
        state["totals"]["correct"] += 1


def update_streak(state: dict):
    """Called when a DAILY goal completes. Consecutive days grow the streak."""
    last = state.get("last_daily")
    t = dt.date.today()
    if last:
        gap = (t - dt.date.fromisoformat(last)).days
        if gap == 0:
            return  # already counted today
        state["streak"] = state["streak"] + 1 if gap == 1 else 1
    else:
        state["streak"] = 1
    state["best_streak"] = max(state["best_streak"], state["streak"])
    state["last_daily"] = t.isoformat()


def run_session(n: int, daily: bool, target: str, use_color: bool,
                input_fn=input, rng: random.Random = None,
                bank: list = None, state: dict = None) -> dict:
    """Run a quiz session. Returns the session summary dict.
    bank/state/input_fn/rng are injectable for tests."""
    rng = rng or random.Random()
    bank = bank or load_questions()
    state = state if state is not None else load_state()

    def c(text, code):
        return f"{code}{text}{RESET}" if use_color else text

    if daily:
        n = state.get("daily_goal", 1)
        if state.get("last_daily") == today():
            print()
            print(f"  {c('✓ Daily already complete.', GREEN)} "
                  f"Streak: {c('🔥 ' + str(state['streak']) + ' day' + ('s' if state['streak'] != 1 else ''), BOLD)}. "
                  "Come back tomorrow, or run a rapid-fire round for extra XP.")
            print()
            return {"mode": "daily", "asked": 0, "correct": 0, "xp": 0, "already_done": True}

    weights = {}
    if target:
        weights = audit_weights(target)
        if weights:
            flagged = ", ".join(sorted(weights, key=weights.get, reverse=True))
            print(f"\n  {c('🎯 Audit-guided training:', BOLD)} your setup was flagged on "
                  f"{c(flagged, YELLOW)}: biasing questions there.")

    questions = select_questions(bank, state, n, weights, rng)
    (thr, remoji, rname), _ = rank_for(state["xp"])

    print()
    print(c("  ╭───────────────────────────────────────────────╮", DIM))
    print(c("  │  👮 HANK ACADEMY · security training           │", BOLD))
    print(c("  ╰───────────────────────────────────────────────╯", DIM))
    mode_label = f"daily ({n} question{'s' if n != 1 else ''})" if daily else f"rapid-fire ({n} questions)"
    print(f"  {remoji} {rname} · {state['xp']} XP · 🔥 {state['streak']}-day streak · mode: {mode_label}")
    print()

    session = {"mode": "daily" if daily else "rapid", "asked": 0, "correct": 0, "xp": 0}
    try:
        for i, q in enumerate(questions, 1):
            correct = ask_question(q, i, len(questions), use_color, input_fn, rng)
            record_answer(state, q, correct)
            session["asked"] += 1
            if correct:
                session["correct"] += 1
                session["xp"] += q["difficulty"] * POINTS_PER_DIFFICULTY
    except (EOFError, KeyboardInterrupt):
        pass

    if session["asked"] == 0:
        return session

    # bonuses
    if session["mode"] == "rapid" and session["asked"] >= 10 and session["correct"] == session["asked"]:
        session["xp"] += PERFECT_ROUND_BONUS
        print(f"  {c('🏆 PERFECT ROUND! +' + str(PERFECT_ROUND_BONUS) + ' XP bonus', GREEN)}")
    if daily and session["asked"] >= n:
        session["xp"] += DAILY_COMPLETE_BONUS
        update_streak(state)
        print(f"  {c('📅 Daily complete! +' + str(DAILY_COMPLETE_BONUS) + ' XP · streak: 🔥 ' + str(state['streak']), GREEN)}")

    old_rank, _ = rank_for(state["xp"])
    state["xp"] += session["xp"]
    new_rank, next_rank = rank_for(state["xp"])
    state["rank"] = {"emoji": new_rank[1], "name": new_rank[2]}
    state["history"].append({"date": today(), "mode": session["mode"],
                             "asked": session["asked"], "correct": session["correct"],
                             "xp": session["xp"]})

    fresh = check_new_badges(state, session)
    save_state(state)

    # ---- summary ----
    pct = round(100 * session["correct"] / session["asked"])
    print(f"  {c('Session:', BOLD)} {session['correct']}/{session['asked']} correct ({pct}%) · "
          f"{c('+' + str(session['xp']) + ' XP', GREEN)} → {state['xp']} XP total")
    if new_rank[0] != old_rank[0]:
        print(f"  {c('🎉 RANK UP → ' + new_rank[1] + ' ' + new_rank[2], BOLD)}")
    elif next_rank:
        need = next_rank[0] - state["xp"]
        print(f"  {c(f'{need} XP to {next_rank[1]} {next_rank[2]}', DIM)}")
    for b in fresh:
        print(f"  {c('🎖  New badge: ' + b['emoji'] + ' ' + b['name'] + ': ' + b['desc'], YELLOW)}")
    if state["badges"]:
        shelf = " ".join(b["emoji"] for b in state["badges"])
        print(f"  {c('Badge shelf: ' + shelf, DIM)}")
    print(f"  {c('Your rank shows on the next audit report card (hank_audit.py --html).', DIM)}")
    print()
    return session


def print_stats(state: dict, use_color: bool):
    def c(text, code):
        return f"{code}{text}{RESET}" if use_color else text

    (thr, remoji, rname), nxt = rank_for(state["xp"])
    print()
    print(c("  ╭───────────────────────────────────────────────╮", DIM))
    print(c("  │  👮 HANK ACADEMY · your record                 │", BOLD))
    print(c("  ╰───────────────────────────────────────────────╯", DIM))
    print(f"  Rank: {c(remoji + ' ' + rname, BOLD)} · {state['xp']} XP"
          + (f" · {nxt[0] - state['xp']} XP to {nxt[1]} {nxt[2]}" if nxt else " · max rank!"))
    print(f"  Streak: 🔥 {state['streak']} day(s) (best {state['best_streak']}) · "
          f"daily goal: {state.get('daily_goal', 1)}/day")
    t = state["totals"]
    acc = round(100 * t["correct"] / t["asked"]) if t["asked"] else 0
    print(f"  Answered: {t['asked']} questions · {t['correct']} correct ({acc}%)")
    print()
    print(c("  By category:", BOLD))
    for cat in CATEGORIES:
        s = state["category_stats"].get(cat, {"asked": 0, "correct": 0})
        pct = round(100 * s["correct"] / s["asked"]) if s["asked"] else 0
        bar = "▰" * (pct // 10) + "▱" * (10 - pct // 10)
        mastered = " 🎖" if s.get("correct", 0) >= MASTERY_THRESHOLD else ""
        print(f"    {CATEGORY_LABEL[cat]:<18} {bar} {pct:>3}% ({s['correct']}/{s['asked']}){mastered}")
    print()
    if state["badges"]:
        print(c("  Badges:", BOLD))
        for b in state["badges"]:
            print(f"    {b['emoji']} {b['name']}: {b.get('desc', '')} ({b['earned']})")
    else:
        print(c("  No badges yet. Run a session; the first one's guaranteed. 🎓", DIM))
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description="Hank Academy: security training quiz.")
    p.add_argument("-n", "--questions", type=int, default=10,
                   help="questions per rapid-fire round (default: 10)")
    p.add_argument("--daily", action="store_true",
                   help="run today's daily question(s) and keep the streak alive")
    p.add_argument("--daily-goal", type=int, choices=range(1, 6), metavar="1-5",
                   help="set how many questions the daily requires (1-5)")
    p.add_argument("--target", metavar="DIR",
                   help="run the audit on DIR and bias questions toward what it flags")
    p.add_argument("--stats", action="store_true", help="show your Academy dashboard")
    p.add_argument("--reset", action="store_true", help="wipe all Academy progress")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = p.parse_args(argv)

    use_color = sys.stdout.isatty() and not args.no_color
    state = load_state()

    if args.reset:
        confirm = input("  Really wipe all Academy progress? [y/N] ").strip().lower()
        if confirm == "y":
            save_state(fresh_state())
            print("  Progress wiped. Back to Cadet. 🎓")
        return 0

    if args.daily_goal:
        state["daily_goal"] = args.daily_goal
        save_state(state)
        print(f"  Daily goal set to {args.daily_goal} question(s)/day.")
        if not args.daily:
            return 0
        state = load_state()

    if args.stats:
        print_stats(state, use_color)
        return 0

    n = max(1, min(args.questions, 25))
    run_session(n, daily=args.daily, target=args.target, use_color=use_color, state=state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
