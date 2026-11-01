"""Explicit fake model outputs for transport/service tests, never model evidence."""
from brain_core import trainer

def output(scenario):
    result=trainer.infer(scenario,'',{}, {},mock=True)
    result.pop('_provenance')
    result['narrative']='I would review what happened and acknowledge uncertainty before taking a proportionate step.'
    result['decision']={'conflicting_emotions':['concern','curiosity'],
                        'evidence':scenario,'uncertainty':'Other people\'s motives remain unknown.',
                        'options':['Discuss the reported facts calmly','Pause before making an irreversible choice'],
                        'recommended_action':'Discuss the reported facts calmly',
                        'rationale':'I would respond proportionately to this reported situation: '+scenario}
    return result
