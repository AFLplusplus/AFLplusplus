"""Scenario-conditioned priors; advisory candidates, never decision overrides."""
import re
from .appraisal import lexical_appraisal, NEUTRAL, state_emotions

def situation(text):
    """Limited lexical cues, not verified facts or full semantic interpretation."""
    s=text.casefold()
    own=bool(re.search(r'\b(?:i|you) made a mistake\b',s))
    blame=bool(re.search(r'\b(?:coworker|colleague)\b',s) and re.search(r'\b(?:blamed|blaming)\b',s))
    jealous=bool(re.search(r'\b(?:jealous|jealousy|jelous)\b',s))
    no_evidence=bool(re.search(r'\b(?:no evidence|without evidence) of (?:dishonesty|cheating)\b',s))
    return {'own_error_affecting_colleague':own and blame,
            'jealousy_without_dishonesty_evidence':jealous and no_evidence,
            'reported_events':[x.strip() for x in re.split(r'[.!?\n]+',text) if x.strip()][:4],
            'status':'Reported claims; lexical cues can miss nuance.'}

def assess(scenario, profile, temporary_state, *, relationship_state=None, experiences=None):
    prior=state_emotions(temporary_state.get('emotions',NEUTRAL))
    cues=lexical_appraisal(scenario);relation=relationship_state or {}
    emotions={k:round(.2*prior[k]+.7*cues[k]+.1*relation.get(k,prior[k]),4) for k in NEUTRAL}
    return build_context(profile,prior,relation,emotions,experiences or [],scenario=scenario)

def build_context(profile, prior, relationship, emotions, experiences, *, scenario=''):
    t,e=profile['traits'],state_emotions(emotions);event=situation(scenario)
    responsibility=1.0 if event['own_error_affecting_colleague'] else 0.0
    fairness=1.0 if responsibility or event['jealousy_without_dishonesty_evidence'] else .3
    # Concerns about actions are separate from both emotions and stable traits.
    options=[('seek_clarity',.25*t['curiosity'],.2*e['caution'],.1,
              'Ask about specific missing facts; improves clarity but may delay necessary action.'),
             ('pause_and_regulate',.2*t['emotional_stability'],.25*e['fear']+.2*e['anger'],.1,
              'Pause before reacting; reduces impulsivity but alone does not repair harm.')]
    if responsibility:
        affected=['self: reputation and promotion','coworker: unfair blame and trust','team: accurate accountability']
        motivations=['repair harm and fairness','reputation and fear of consequences','responsibility and honesty']
        options += [('admit_and_repair',.3*t['conscientiousness'],.3*e['guilt']+.15*e['empathy'],.4*responsibility,
                     'Acknowledge my error, correct blame and offer repair; risks reputation but protects the coworker.'),
                    ('verify_and_correct_record',.2*t['conscientiousness'],.15*e['caution'],.2*fairness,
                     'Check relevant facts promptly and correct the record; avoids inaccuracies but delay prolongs harm.')]
    elif event['jealousy_without_dishonesty_evidence']:
        affected=['self: jealousy and fear of loss','partner: autonomy, trust and openness']
        motivations=['attachment and reassurance','fairness and trust without accusations','fear versus autonomy']
        options += [('regulate_and_communicate',.2*t['empathy_orientation'],.2*e['jealousy']+.15*e['attachment']+.1*e['fear'],.25*fairness,
                     'Own my jealousy and discuss reassurance without accusations or restrictions; supports trust but needs vulnerability.'),
                    ('trust_and_observe',.15*t['emotional_stability'],.25*e['trust'],.2*fairness,
                     'Respect the disclosed friendship and observe actual conduct; preserves autonomy but feelings need care.')]
    else:
        affected=['identify the interests of each person described in the scenario']
        motivations=['fairness and responsibility','trust and attachment','evidence and proportionate self-protection']
        options += [('explore_repair',.2*t['agreeableness'],.2*e['empathy']+.15*e['hope'],.1,
                     'Discuss a concrete repair if harm occurred; helps relationships but needs willingness from those affected.')]
    preferences=sorted([{'option':n,'score':round(a+b+c,4),'trait_contribution':round(a,4),
                          'emotion_contribution':round(b,4),'context_contribution':round(c,4),'consequences':d}
                         for n,a,b,c,d in options],key=lambda x:x['score'],reverse=True)
    return {'method':'scenario-conditioned lexical heuristics; not validated psychology',
            'stable_identity_id':profile['identity_id'],'stable_traits':dict(t),
            'previous_temporary_emotions':dict(prior),'relationship_emotions':dict(relationship),
            'appraised_emotions_before_decision':e,'previous_experiences':experiences,
            'scenario_analysis':event,'affected_parties':affected,
            'concerns':{'responsibility':responsibility,'fairness':fairness},
            'evidence_policy':'Reported events are claims; unknown motives and feelings are not evidence of wrongdoing.',
            'competing_motivations':motivations,'decision_preferences':preferences,
            'authority':'Advisory candidates only; model can propose other options. No emotion or recalled rule authorizes action.'}
