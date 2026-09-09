"""AI analysis components.

Nothing is imported here on purpose: loading scikit-learn and spaCy costs
several seconds and a few hundred MB, so `app.services.analysis` imports the
singletons lazily inside the request path instead.

Import the objects directly, e.g.::

    from app.ai.classifier import classifier
"""
