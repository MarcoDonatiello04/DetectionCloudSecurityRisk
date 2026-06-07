"""
Gestisce l'esecuzione di operazioni asincrone in background.
Responsabilità:
- Fornire un meccanismo basato su QRunnable e QThreadPool per non bloccare la GUI.
- Gestione dei segnali di callback (successo, errore, progresso).
"""

import sys
import traceback
from PySide6.QtCore import QRunnable, QObject, Signal, Slot

class WorkerSignals(QObject):
    """
    Definisce i segnali disponibili per un worker in esecuzione.
    """
    finished = Signal()
    error = Signal(tuple)
    result = Signal(object)
    progress = Signal(int)


class ThreadWorker(QRunnable):
    """
    Rappresenta un worker generico da eseguire in un thread in background.
    """

    def __init__(self, fn, *args, **kwargs):
        """
        Inizializza il worker con la funzione da eseguire e i relativi argomenti.
        """
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        # Aggiunge opzionalmente una callback di progresso se passata nei kwargs
        if 'progress_callback' in kwargs:
            self.kwargs['progress_callback'] = self.signals.progress

    @Slot()
    def run(self):
        """
        Esegue la funzione passata e gestisce l'emissione dei segnali corretti.
        """
        try:
            res = self.fn(*self.args, **self.kwargs)
        except Exception as e:
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(res)
        finally:
            self.signals.finished.emit()
