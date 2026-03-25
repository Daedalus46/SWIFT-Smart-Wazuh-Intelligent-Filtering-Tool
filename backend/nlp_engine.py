"""
SWIFT NLP Engine — AI-Powered Structured Incident Report Generation
Uses google/flan-t5-small for natural language incident analysis.
Produces multi-section structured reports with risk scoring.
Lazy-loads the model on first call to avoid slowing down server startup.
"""
import torch
from typing import List, Dict, Any

# Global state for lazy loading
_model = None
_tokenizer = None


def _get_device() -> str:
    """Detect best available hardware -- GPU if present, else CPU."""
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


def _load_model() -> None:
    """Lazy-load the Flan-T5-Small model and tokenizer on first use."""
    global _model, _tokenizer
    if _model is not None:
        return

    from transformers import T5ForConditionalGeneration, T5Tokenizer

    model_name = "google/flan-t5-small"
    device = _get_device()

    print(f"[NLP Engine] Loading {model_name} on {device.upper()}...")
    _tokenizer = T5Tokenizer.from_pretrained(model_name)
    _model = T5ForConditionalGeneration.from_pretrained(model_name).to(device)
    print(f"[NLP Engine] Model loaded successfully on {device.upper()}.")


def _run_t5(prompt: str, max_tokens: int = 200) -> str:
    """Run a single T5 inference pass with the given prompt."""
    assert _model is not None and _tokenizer is not None
    device = _get_device()
    inputs = _tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True).to(device)
    with torch.no_grad():
        outputs = _model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            num_beams=4,
            early_stopping=True,
            no_repeat_ngram_size=3,
        )
    return _tokenizer.decode(outputs[0], skip_special_tokens=True)


def _compute_risk_level(
    total_logs: int,
    malicious_count: int,
    threat_summaries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute overall risk level from threat data."""
    if total_logs == 0:
        return {"level": "NONE", "score": 0, "color": "emerald"}

    mal_ratio = malicious_count / total_logs
    max_confidence = max(
        (float(t.get("ai_confidence_score", 0)) for t in threat_summaries),
        default=0,
    )
    # Risk score: weighted combination of malicious ratio and max confidence
    risk_score = round((mal_ratio * 60) + (max_confidence / 100 * 40), 1)

    if risk_score >= 70 or mal_ratio > 0.5:
        return {"level": "CRITICAL", "score": risk_score, "color": "red"}
    elif risk_score >= 45 or mal_ratio > 0.3:
        return {"level": "HIGH", "score": risk_score, "color": "orange"}
    elif risk_score >= 20 or mal_ratio > 0.1:
        return {"level": "MEDIUM", "score": risk_score, "color": "yellow"}
    else:
        return {"level": "LOW", "score": risk_score, "color": "emerald"}


def _categorize_threats(
    threat_summaries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Group threats by MITRE tactic for categorized display."""
    tactic_map: Dict[str, Dict[str, Any]] = {}
    for t in threat_summaries:
        tactic = str(t.get("mitre_tactic", "Unknown"))
        if tactic not in tactic_map:
            tactic_map[tactic] = {
                "tactic": tactic,
                "threat_count": 0,
                "total_occurrences": 0,
                "threats": [],
            }
        tactic_map[tactic]["threat_count"] += 1
        tactic_map[tactic]["total_occurrences"] += int(t.get("occurrence_count", 1))
        tactic_map[tactic]["threats"].append(str(t.get("rule_description", "Unknown")))

    # Sort by total occurrences descending
    return sorted(tactic_map.values(), key=lambda x: x["total_occurrences"], reverse=True)


def _build_summary_prompt(
    total_logs: int,
    benign_count: int,
    malicious_count: int,
    threat_summaries: List[Dict[str, Any]],
    risk_level: str,
) -> str:
    """Build a focused executive summary prompt."""
    threat_lines = []
    for t in threat_summaries[:6]:
        threat_lines.append(
            f"- {t.get('rule_description', 'Unknown')} "
            f"(Tactic: {t.get('mitre_tactic', 'N/A')}, "
            f"Occurrences: {t.get('occurrence_count', 1)}, "
            f"Confidence: {t.get('ai_confidence_score', 0)}%)"
        )
    threat_block = "\n".join(threat_lines) if threat_lines else "None"

    return (
        f"Write a detailed executive cybersecurity incident summary:\n\n"
        f"Risk Level: {risk_level}\n"
        f"Total logs: {total_logs}, Benign: {benign_count}, Malicious: {malicious_count}\n"
        f"Threat ratio: {round(malicious_count / max(total_logs, 1) * 100, 1)}%\n"
        f"Threats detected:\n{threat_block}\n\n"
        f"Write 2-3 sentences analyzing the severity and attack patterns observed."
    )


def _build_recommendations_prompt(
    threat_summaries: List[Dict[str, Any]],
    risk_level: str,
) -> str:
    """Build a prompt for generating actionable recommendations."""
    tactics = set(str(t.get("mitre_tactic", "")) for t in threat_summaries[:5])
    descriptions = [str(t.get("rule_description", "")) for t in threat_summaries[:5]]

    return (
        f"Given these cybersecurity threats at {risk_level} risk:\n"
        f"Attack types: {', '.join(descriptions)}\n"
        f"MITRE tactics: {', '.join(tactics)}\n\n"
        f"List exactly 3 specific, actionable steps a SOC analyst should take immediately."
    )


def generate_structured_report(
    total_logs: int,
    benign_count: int,
    malicious_count: int,
    threat_summaries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Generate a multi-section structured incident report.

    Returns a dict with: risk_assessment, executive_summary,
    threat_categories, priority_actions, and metadata.
    """
    _load_model()

    # 1. Compute risk level (no model needed)
    risk = _compute_risk_level(total_logs, malicious_count, threat_summaries)

    # 2. Categorize threats by MITRE tactic
    categories = _categorize_threats(threat_summaries)

    # 3. Generate executive summary via NLP
    summary_prompt = _build_summary_prompt(
        total_logs, benign_count, malicious_count, threat_summaries, risk["level"]
    )
    raw_summary = _run_t5(summary_prompt, max_tokens=200)

    # Enrich short summaries with data-driven context
    mal_pct = round((malicious_count / max(total_logs, 1)) * 100, 1)
    if len(raw_summary.split()) < 15:
        top_threats = ", ".join(
            str(t.get("rule_description", "Unknown")) for t in threat_summaries[:3]
        )
        executive_summary = (
            f"Security analysis of {total_logs} log events identified "
            f"{malicious_count} malicious events ({mal_pct}% threat ratio), "
            f"classified at {risk['level']} risk (score: {risk['score']}/100). "
            f"Primary attack vectors include: {top_threats}. "
            f"{raw_summary} "
            f"All findings have been mapped to MITRE ATT&CK for triage prioritization."
        )
    else:
        executive_summary = raw_summary

    # 4. Generate recommendations via NLP
    if threat_summaries:
        rec_prompt = _build_recommendations_prompt(threat_summaries, risk["level"])
        raw_recs = _run_t5(rec_prompt, max_tokens=150)
        # Parse numbered list or fallback
        priority_actions = [
            line.strip().lstrip("0123456789.-) ") for line in raw_recs.split("\n") if line.strip()
        ]
        if len(priority_actions) < 2:
            priority_actions = [raw_recs]
    else:
        priority_actions = ["No immediate actions required. Continue monitoring."]

    # 5. Build top threats ranked list
    ranked_threats = sorted(
        threat_summaries,
        key=lambda t: (float(t.get("ai_confidence_score", 0)) * int(t.get("occurrence_count", 1))),
        reverse=True,
    )[:5]

    top_threat_vectors = [
        {
            "description": str(t.get("rule_description", "Unknown")),
            "tactic": str(t.get("mitre_tactic", "N/A")),
            "occurrences": int(t.get("occurrence_count", 1)),
            "confidence": float(t.get("ai_confidence_score", 0)),
        }
        for t in ranked_threats
    ]

    return {
        "risk_assessment": risk,
        "executive_summary": executive_summary,
        "threat_categories": categories,
        "top_threat_vectors": top_threat_vectors,
        "priority_actions": priority_actions,
        "stats": {
            "total_logs": total_logs,
            "benign_count": benign_count,
            "malicious_count": malicious_count,
            "threat_ratio_pct": mal_pct,
            "unique_threat_types": len(threat_summaries),
            "unique_tactics": len(categories),
        },
    }
