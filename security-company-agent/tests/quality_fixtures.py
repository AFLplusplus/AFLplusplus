"""Explicit fake model outputs for transport/service tests, never model evidence."""
from pathlib import Path
import tempfile
from brain_core import trainer

def output(scenario):
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        result = trainer.infer(scenario, '', {}, {}, mock=True, state_path=root / 'state.json',
                               history_path=root / 'history.json', data_dir=root,
                               db_path=root / 'brain.sqlite3')
    result.pop('_provenance')
    result['narrative']='I would review what happened and acknowledge uncertainty before taking a proportionate step.'
    result['decision']={'conflicting_emotions':['concern','curiosity'],
                        'evidence':scenario,'uncertainty':'Other people\'s motives remain unknown.',
                        'options':['Discuss the reported facts calmly','Pause before making an irreversible choice'],
                        'recommended_action':'Discuss the reported facts calmly',
                        'rationale':'I would respond proportionately to this reported situation: '+scenario}
    return result
