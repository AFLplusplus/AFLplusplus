"""Sovereign Brain trainer UI, independent from Hermes and operational agents."""
import json
import streamlit as st
from brain_core import trainer, studio, service, personality
from brain_core.appraisal import EMOTIONS, NEUTRAL
from brain_core.model_api import ModelConfig, ModelError, local_inventory
from brain_core.runtime_guard import available_memory_gib

st.set_page_config(page_title='Sovereign Brain | Training Studio', page_icon='🧠', layout='wide')
st.title('🧠 Sovereign Brain')
st.caption('Train the Brain · simulated emotions · decisions you can challenge')
st.info('Emotional indexes are computational simulations, not feelings or biological measurements. '
        'Saved feedback can be retrieved as context; it does not update model weights.')
try:
    profile = personality.load()
except (personality.PersonalityError, OSError):
    st.error('The established personality is missing, invalid, or unreadable. No identity was reset. '
             'Restore the local personality from backup before continuing.')
    st.stop()

@st.cache_data(ttl=10)
def installed_models():
    return local_inventory()

models = installed_models()
ready = 'qwen3:1.7b' in models
config, configuration_error = None, None
if 'studio_last_turn' not in st.session_state:
    st.session_state.studio_last_turn = None

with st.sidebar:
    st.subheader('Model connection')
    with st.expander('Persistent personality'):
        st.write(profile['identity_name'])
        st.caption('Identity: ' + profile['identity_id'])
        st.write(profile['mission'])
        for name, value in profile['traits'].items():
            st.progress(float(value), text=f'{name.replace("_", " ").title()}: {value:.2f}')
        st.caption('Stable traits persist independently from temporary emotions. They do not grant execution authority.')
    mode = st.radio('Inference', ['Local model (Ollama)', 'Enterprise gateway', 'Offline demonstration'],
                    index=0 if ready else 2, key='studio_inference',
                    help='Offline mode uses a fixed response and lexical visualization, not model reasoning.')
    mock = mode == 'Offline demonstration'
    remote_authorized = False
    if mock:
        st.warning('Offline demonstration: fixed example response, not actual model reasoning. '
                   'Emotion bars use transparent word matching only.')
    elif mode == 'Local model (Ollama)':
        config = ModelConfig()
        st.caption('Local endpoint: 127.0.0.1:11434 · requested model: qwen3:1.7b')
        st.write('Model inventory:', 'qwen3:1.7b available' if ready else 'Requested model not detected')
        if not ready:
            configuration_error = 'Local model is not installed or Ollama is not responding.'
    else:
        remote_authorized = st.checkbox('Authorize sending this session, retrieved feedback and selected '
                                       'reference excerpts to my configured enterprise gateway.', value=False)
        try:
            config = ModelConfig.from_env(allow_remote=remote_authorized)
            if config.local:
                configuration_error = 'Configure BRAIN_API_BASE and BRAIN_MODEL for your enterprise gateway.'
            st.caption('Enterprise settings come from environment variables. Credentials are never displayed.')
        except (ModelError, ValueError):
            configuration_error = 'A valid HTTPS gateway and explicit session-data authorization are required.'
    memory = available_memory_gib()
    if memory is not None:
        st.caption(f'Available RAM: {memory:.2f} GiB')
        if memory < 2.5:
            st.warning('Low available RAM. New local model loading is held until at least 2.5 GiB is free; '
                       '3 GiB is preferred for the first test.')
    if configuration_error:
        st.warning(configuration_error)
    if st.button('Refresh connection status'):
        installed_models.clear()
        st.rerun()
    st.divider()
    state, history = trainer.status()
    st.subheader('Training memory')
    st.metric('Iterations', state['iterations'])
    st.write('Simulated emotion:', state['emotion'])
    st.caption(f"Saved proposed rules: {len(history['rules'])}. Rules are not autonomous actions.")
    with st.expander('Legacy simulated chemistry'):
        for key in ('dopamine', 'cortisol', 'serotonin'):
            st.write(f'{key.title()}: {state["metrics"][key]} / 100')
    st.caption('Local records are not encrypted. Keep the app bound to loopback.')

train_tab, docs_tab, research_tab, history_tab = st.tabs(
    ['💬 Train the Brain', '📚 Documents', '🌍 Research', '📈 Training history'])

with train_tab:
    st.subheader('Talk to the Brain')
    st.caption('One persistent simulated identity. A message can be a question, a situation, or a decision to explore.')
    scenario = st.text_area('Situation', height=135, max_chars=8000,
                           placeholder='Describe the emotional conflict and the decision to consider.')
    context = st.text_area('Context and relationships (optional)', height=80, max_chars=3000)
    relationship_label = st.text_input('Relationship or context label (optional)', max_chars=100,
                                       help='Use the same label to recall emotions for this relationship. Leave empty to keep contexts separate.')
    guidance = st.text_area('Your guidance (optional)', height=75, max_chars=4000,
                            placeholder='What should the Brain pay attention to?')
    use_memory = st.checkbox('Retrieve relevant previous trainer corrections', value=True)
    use_refs = st.checkbox('Use relevant uploaded documents and approved research', value=False)
    if mode == 'Enterprise gateway' and use_refs:
        st.warning('Selected excerpts will leave this computer only after the explicit gateway authorization above.')
    combined = scenario.strip() + ('\n\nContext and relationships: ' + context.strip() if context.strip() else '')
    corrections = studio.feedback_context(combined) if use_memory and scenario.strip() else []
    if corrections:
        with st.expander(f'Previous corrections available for this session ({len(corrections)})'):
            for correction in corrections:
                st.write(f"Training turn #{correction['turn_id']} · {correction['rating']}")
                st.write(correction['correction'])
    if st.button('Analyze emotions and decide', type='primary',
                 disabled=not scenario.strip() or bool(configuration_error)):
        try:
            with st.spinner('Analyzing locally...' if not mock and config and config.local else 'Preparing response...'):
                turn_id, updated, result, retrieved = service.analyze(
                    combined, guidance, mock=mock, config=config,
                    use_references=use_refs, use_feedback=use_memory,
                    relationship_label=relationship_label)
            st.session_state.studio_last_turn = turn_id
            st.session_state.studio_result = result
            st.session_state.studio_state = updated
            st.session_state.studio_feedback = retrieved
            st.rerun()
        except (ModelError, ValueError) as error:
            st.error(str(error))
        except Exception:
            st.error('The session could not be saved. Check local storage and try again. '
                     'No operational agents were invoked.')
    if st.session_state.studio_last_turn is not None:
        result = st.session_state.studio_result
        updated = st.session_state.studio_state
        provenance = result.get('_provenance', {})
        if provenance.get('source') == 'offline_fixture':
            st.warning('This result is an offline fixture. It is not an analysis by a pretrained model.')
        else:
            st.success(f"Model response: {provenance.get('model')} · {provenance.get('seconds')} seconds")
        st.subheader('First-person simulated response')
        st.write(result['narrative'])
        decision = result['decision']
        left, right = st.columns(2)
        with left:
            st.markdown('**Competing emotions**')
            for emotion in decision['conflicting_emotions']:
                st.write('• ' + emotion)
            st.markdown('**Evidence and uncertainty**')
            st.write(decision['evidence'])
            st.write(decision['uncertainty'])
        with right:
            st.markdown('**Options considered**')
            for option in decision['options']:
                st.write('• ' + option)
            st.markdown('**Proposed decision**')
            st.write(decision['recommended_action'])
            st.markdown('**Why this recommendation**')
            st.write(decision['rationale'])
        st.subheader('Simulated emotional state — before and after')
        before = result.get('_before_state', {}).get('emotions', NEUTRAL)
        after = updated.get('emotions', NEUTRAL)
        chart = [{'Emotion': name.replace('_', ' ').title(),
                  'Before': before.get(name, 0.5), 'After': after[name]} for name in EMOTIONS]
        st.bar_chart(chart, x='Emotion', y=['Before', 'After'], horizontal=True, stack=False)
        st.dataframe(chart,
                     hide_index=True, width='stretch')
        ids = result.get('_feedback_turn_ids', [])
        st.caption('Retrieved trainer corrections used as context: ' + (', '.join(map(str, ids)) if ids else 'none'))
        with st.expander('Inspect appraisal and decision preferences'):
            st.caption('These transparent heuristic scores are computed before inference. '
                       'They are not proof of genuine emotional reasoning.')
            st.json(result.get('_cognitive_context', {}))
        rating = st.radio('Rate emotional appropriateness', ['good', 'partial', 'poor'], horizontal=True,
                          key=f"rating_{st.session_state.studio_last_turn}")
        correction = st.text_area('Correct the response / challenge its recommendation', max_chars=4000,
                                   key=f"correction_{st.session_state.studio_last_turn}")
        if st.button('Save trainer feedback'):
            service.give_feedback(st.session_state.studio_last_turn, rating, correction)
            st.success('Feedback saved locally. Relevant corrections can be retrieved in later sessions; '
                       'model weights have not changed.')
    else:
        st.subheader('Current simulated emotional state')
        for name, value in state.get('emotions', NEUTRAL).items():
            st.progress(float(value), text=f'{name.replace("_", " ").title()}: {value:.2f}')

with docs_tab:
    st.subheader('Local reference documents')
    uploads = st.file_uploader('Upload PDF, DOCX, TXT or Markdown', type=['pdf', 'docx', 'txt', 'md'],
                               accept_multiple_files=True, max_upload_size=10)
    if st.button('Import uploaded documents', disabled=not uploads):
        for upload in uploads:
            try:
                text = studio.decode_document(upload.name, upload.getvalue())
                studio.add_document(upload.name, text)
                st.success(f'Indexed {upload.name} ({len(text):,} characters)')
            except Exception:
                st.warning('Document import failed. Check its type, size and readable text.')
    st.caption('Documents stay in local SQLite storage. References are opt-in per session. '
               'Remote inference requires explicit authorization; scanned PDFs need OCR, which is not enabled.')
    for document in studio.documents():
        st.write(f"📄 {document['filename']} — {document['char_count']:,} characters")

with research_tab:
    st.subheader('Trainer-controlled research')
    st.write('Search runs only when you request it. Candidate sources require review before retrieval.')
    topic = st.text_input('Research question', max_chars=500)
    if st.button('Find evidence', disabled=not topic.strip()):
        try:
            found = studio.research_search(topic)
            st.success(f'Saved {len(found)} candidate sources for review.')
        except Exception:
            st.error('Research unavailable. Check the optional research provider configuration.')
    for item in studio.research_items():
        with st.expander(item['title'] or item['url']):
            st.write('Source:', item['url'])
            st.write(item['excerpt'])
            approved = st.checkbox('Approve as reference evidence', value=bool(item['approved']),
                                   key=f"research_{item['id']}")
            if st.button('Save approval', key=f"approve_{item['id']}"):
                studio.approve_research(item['id'], approved)
                st.success('Reference status updated. Behavioral rules were not overwritten.')

with history_tab:
    st.subheader('Your training history')
    records = studio.recent_turns(50)
    st.metric('Saved training scenarios (latest 50)', len(records))
    for row in records:
        with st.expander(f"#{row['id']} · {row['scenario'][:95]}"):
            st.write('Scenario:', row['scenario'])
            st.write('Trainer guidance:', row['feedback'] or 'None')
            st.write('Rating:', row['rating'] or 'Not yet rated')
            st.write('Correction:', row['commentary'] or 'None')
            result = json.loads(row['result_json'])
            st.write('Response source:', result.get('_provenance', {}).get('source', 'legacy record — see original history mode'))
            st.write('Persistent identity:', result.get('_personality_id', 'legacy record predating identity tracking'))
            st.json(result)
    st.caption('Persistent contextual adaptation is retrieval of prior corrections. It is not fine-tuning, '
               'and inclusion in a prompt does not prove a model followed the correction.')
