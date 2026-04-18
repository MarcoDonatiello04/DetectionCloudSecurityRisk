from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

class ICloudScanner(ABC):
    """
    Interfaccia base per gli scanner di Infrastructure as Code (IaC).
    Definisce i controlli e i metodi fondamentali che ogni parser (es. Terraform, CloudFormation) dovrà implementare.
    """

    @abstractmethod
    def parse_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Legge e analizza un singolo file IaC.

        :param file_path: Percorso del file da scansionare.
        :return: Struttura dati (es. dizionario) risultante dal parsing o None in caso di errore.
        """
        pass

    @abstractmethod
    def extract_resources(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Estrae la lista delle risorse definite nei dati parsati.

        :param parsed_data: Dizionario ottenuto tramite parse_file.
        :return: Lista di dizionari rappresentanti le risorse estratte (chiavi attese: type, name, config).
        """
        pass

    @abstractmethod
    def scan_folder(self, folder_path: str) -> Dict[str, Dict[str, Any]]:
        """
        Scansiona ricorsivamente una cartella alla ricerca di file supportati e li analizza.

        :param folder_path: Il percorso della directory di partenza.
        :return: Un dizionario chiave-valore con { "file_path": dati_parsati }.
        """
        pass

    @abstractmethod
    def print_summary(self, parsed_files: Dict[str, Dict[str, Any]]) -> None:
        """
        Mostra o esporta il riepilogo delle risorse trovate e la loro configurazione.

        :param parsed_files: Il dizionario di file analizzati con relative risorse e configurazioni.
        """
        pass
