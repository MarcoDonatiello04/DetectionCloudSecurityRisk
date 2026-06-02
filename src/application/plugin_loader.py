import os
import sys
import importlib.util
import logging
from typing import List, Type, Dict
from src.domain.interfaces import IDetector, IRemediation
from src.domain.exceptions import PluginLoadException

logger = logging.getLogger("SecurityPlatform.PluginLoader")


class PluginLoader:
    """
    Manager responsabile del caricamento dinamico dei moduli Python contenenti 
    le classi concrete di IDetector o IRemediation.
    """

    def __init__(self, plugins_dir: str):
        """
        Inizializza il PluginLoader registrando il percorso dei plugin.

        Args:
            plugins_dir (str): Percorso della directory dei plugin.
        """
        self.plugins_dir = os.path.abspath(plugins_dir)
        # Assicuriamo che la directory dei plugin sia nel PYTHONPATH
        if self.plugins_dir not in sys.path:
            sys.path.insert(0, self.plugins_dir)

    def load_detectors(self) -> List[IDetector]:
        """
        Trova e istanzia tutti i detector concreti all'interno della cartella dei plugin.

        Returns:
            List[IDetector]: Lista di istanze concrete di IDetector caricate.

        Raises:
            PluginLoadException: Se si verifica un errore durante l'istanziazione di un detector.
        """
        detectors: List[IDetector] = []
        detectors_dir = os.path.join(self.plugins_dir, "detectors")
        
        if not os.path.exists(detectors_dir):
            logger.warning(f"La directory dei detector {detectors_dir} non esiste.")
            return detectors

        logger.info(f"Ricerca detector in corso nella cartella: {detectors_dir}")
        for root, _, files in os.walk(detectors_dir):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    filepath = os.path.join(root, file)
                    module_name = file[:-3]
                    
                    try:
                        # Caricamento dinamico del file sorgente
                        spec = importlib.util.spec_from_file_location(module_name, filepath)
                        if spec and spec.loader:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            
                            # Cerca classi che ereditano da IDetector
                            for attribute_name in dir(module):
                                attribute = getattr(module, attribute_name)
                                if (isinstance(attribute, type) and 
                                        issubclass(attribute, IDetector) and 
                                        attribute is not IDetector):
                                    try:
                                        detector_instance = attribute()
                                        detectors.append(detector_instance)
                                        logger.info(f"Caricato con successo il Detector Plugin: {detector_instance.name} ({attribute_name})")
                                    except Exception as ex:
                                        raise PluginLoadException(f"Impossibile istanziare {attribute_name} in {file}: {ex}")
                    except (ImportError, SyntaxError) as e:
                        logger.error(f"Errore di importazione o sintassi nel modulo {filepath}: {e}")
                    except Exception as e:
                        logger.error(f"Errore generico durante il caricamento del modulo {filepath}: {e}")
                        
        return detectors

    def load_remediations(self) -> Dict[str, IRemediation]:
        """
        Trova e istanzia tutte le remediation, indicizzandole per target_category.

        Returns:
            Dict[str, IRemediation]: Dizionario delle remediation istanziate, indicizzato per categoria.

        Raises:
            PluginLoadException: Se si verifica un errore durante l'istanziazione di una remediation.
        """
        remediations: Dict[str, IRemediation] = {}
        remediations_dir = os.path.join(self.plugins_dir, "remediations")
        
        if not os.path.exists(remediations_dir):
            logger.warning(f"La directory delle remediation {remediations_dir} non esiste.")
            return remediations

        for root, _, files in os.walk(remediations_dir):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    filepath = os.path.join(root, file)
                    module_name = file[:-3]
                    
                    try:
                        spec = importlib.util.spec_from_file_location(module_name, filepath)
                        if spec and spec.loader:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            
                            for attribute_name in dir(module):
                                attribute = getattr(module, attribute_name)
                                if (isinstance(attribute, type) and 
                                        issubclass(attribute, IRemediation) and 
                                        attribute is not IRemediation):
                                    try:
                                        remediation_instance = attribute()
                                        remediations[remediation_instance.target_category] = remediation_instance
                                        logger.info(f"Caricata Remediation per {remediation_instance.target_category} ({attribute_name})")
                                    except Exception as ex:
                                        raise PluginLoadException(f"Impossibile istanziare remediation {attribute_name} in {file}: {ex}")
                    except (ImportError, SyntaxError) as e:
                        logger.error(f"Errore di importazione o sintassi nella remediation {filepath}: {e}")
                    except Exception as e:
                        logger.error(f"Errore generico durante il caricamento della remediation {filepath}: {e}")
                        
        return remediations
