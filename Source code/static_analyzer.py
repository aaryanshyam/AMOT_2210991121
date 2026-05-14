import pefile
import math
import os
import numpy as np
from utils.patterns import SUSPICIOUS_APIS, MITRE_MAPPING

class StaticAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.results = {}

    def calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def get_human_insights(self):
        insights = []
        entropy = self.results.get("SectionsMaxEntropy", 0)
        if entropy > 7.5:
            insights.append("Critical: Packed/Encrypted sections detected. High likelihood of malware payload.")
        
        suspicious_imp = self.results.get("SuspiciousImports", 0)
        if suspicious_imp > 10:
            insights.append("Warning: Large number of sensitive API calls identified (Crypto/File Manipulation).")
            
        return insights

    def analyze(self):
        try:
            self.pe = pefile.PE(self.file_path)
            
            # Feature Extraction (54 Dimensions Aligned with mathur99 benchmark)
            res = {}
            
            # --- PE Header / OPTIONAL Header ---
            res["Machine"] = self.pe.FILE_HEADER.Machine
            res["SizeOfOptionalHeader"] = self.pe.FILE_HEADER.SizeOfOptionalHeader
            res["Characteristics"] = self.pe.FILE_HEADER.Characteristics
            res["MajorLinkerVersion"] = self.pe.OPTIONAL_HEADER.MajorLinkerVersion
            res["MinorLinkerVersion"] = self.pe.OPTIONAL_HEADER.MinorLinkerVersion
            res["SizeOfCode"] = self.pe.OPTIONAL_HEADER.SizeOfCode
            res["SizeOfInitializedData"] = self.pe.OPTIONAL_HEADER.SizeOfInitializedData
            res["SizeOfUninitializedData"] = self.pe.OPTIONAL_HEADER.SizeOfUninitializedData
            res["AddressOfEntryPoint"] = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            res["BaseOfCode"] = self.pe.OPTIONAL_HEADER.BaseOfCode
            try: res["BaseOfData"] = self.pe.OPTIONAL_HEADER.BaseOfData
            except: res["BaseOfData"] = 0
            res["ImageBase"] = self.pe.OPTIONAL_HEADER.ImageBase
            res["SectionAlignment"] = self.pe.OPTIONAL_HEADER.SectionAlignment
            res["FileAlignment"] = self.pe.OPTIONAL_HEADER.FileAlignment
            res["MajorOperatingSystemVersion"] = self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            res["MinorOperatingSystemVersion"] = self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            res["MajorImageVersion"] = self.pe.OPTIONAL_HEADER.MajorImageVersion
            res["MinorImageVersion"] = self.pe.OPTIONAL_HEADER.MinorImageVersion
            res["MajorSubsystemVersion"] = self.pe.OPTIONAL_HEADER.MajorSubsystemVersion
            res["MinorSubsystemVersion"] = self.pe.OPTIONAL_HEADER.MinorSubsystemVersion
            res["SizeOfImage"] = self.pe.OPTIONAL_HEADER.SizeOfImage
            res["SizeOfHeaders"] = self.pe.OPTIONAL_HEADER.SizeOfHeaders
            res["CheckSum"] = self.pe.OPTIONAL_HEADER.CheckSum
            res["Subsystem"] = self.pe.OPTIONAL_HEADER.Subsystem
            res["DllCharacteristics"] = self.pe.OPTIONAL_HEADER.DllCharacteristics
            res["SizeOfStackReserve"] = self.pe.OPTIONAL_HEADER.SizeOfStackReserve
            res["SizeOfStackCommit"] = self.pe.OPTIONAL_HEADER.SizeOfStackCommit
            res["SizeOfHeapReserve"] = self.pe.OPTIONAL_HEADER.SizeOfHeapReserve
            res["SizeOfHeapCommit"] = self.pe.OPTIONAL_HEADER.SizeOfHeapCommit
            res["LoaderFlags"] = self.pe.OPTIONAL_HEADER.LoaderFlags
            res["NumberOfRvaAndSizes"] = self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            
            # --- Sections ---
            res["SectionsNb"] = len(self.pe.sections)
            section_entropies = [self.calculate_entropy(s.get_data()) for s in self.pe.sections]
            res["SectionsMeanEntropy"] = sum(section_entropies)/len(section_entropies) if section_entropies else 0
            res["SectionsMinEntropy"] = min(section_entropies) if section_entropies else 0
            res["SectionsMaxEntropy"] = max(section_entropies) if section_entropies else 0
            
            section_raw_sizes = [s.SizeOfRawData for s in self.pe.sections]
            res["SectionsMeanRawsize"] = sum(section_raw_sizes)/len(section_raw_sizes) if section_raw_sizes else 0
            res["SectionsMinRawsize"] = min(section_raw_sizes) if section_raw_sizes else 0
            res["SectionMaxRawsize"] = max(section_raw_sizes) if section_raw_sizes else 0
            
            section_virt_sizes = [s.Misc_VirtualSize for s in self.pe.sections]
            res["SectionsMeanVirtualsize"] = sum(section_virt_sizes)/len(section_virt_sizes) if section_virt_sizes else 0
            res["SectionsMinVirtualsize"] = min(section_virt_sizes) if section_virt_sizes else 0
            res["SectionMaxVirtualsize"] = max(section_virt_sizes) if section_virt_sizes else 0
            
            # --- Imports (Primary IAT Scan) ---
            res["ImportsNbDLL"] = len(self.pe.DIRECTORY_ENTRY_IMPORT) if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            imports_nb = 0
            imports_ordinal = 0
            suspicious_count = 0
            mitre_techniques = set()
            
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    imports_nb += len(entry.imports)
                    for imp in entry.imports:
                        if imp.import_by_ordinal: imports_ordinal += 1
                        if imp.name:
                            name = imp.name.decode('utf-8', 'ignore')
                            for cat, apis in SUSPICIOUS_APIS.items():
                                if any(api.lower() in name.lower() for api in apis):
                                    suspicious_count += 1
                                    # Cross-reference with MITRE mapping (partial match)
                                    for pattern, tech in MITRE_MAPPING.items():
                                        if pattern.lower() in name.lower():
                                            mitre_techniques.add(tech)

            # --- String-based Signature Fallback (Crucial for Packed/Mock files) ---
            # This ensures the MITRE table populates even if the IAT is obfuscated
            try:
                with open(self.file_path, "rb") as f:
                    content = f.read().decode('utf-8', 'ignore')
                    for pattern, tech in MITRE_MAPPING.items():
                        if pattern in content:
                            mitre_techniques.add(tech)
                            suspicious_count += 3 # Higher weight for string-based signatures
            except: pass
            
            res["ImportsNb"] = imports_nb
            res["ImportsNbOrdinal"] = imports_ordinal
            res["SuspiciousImports"] = suspicious_count
            
            # --- Exports ---
            res["ExportNb"] = len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT') else 0
            
            # --- Resources ---
            resources_nb = 0
            resources_entropy = []
            resources_size = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    resources_nb += 1
                                    data = self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    resources_entropy.append(self.calculate_entropy(data))
                                    resources_size.append(resource_lang.data.struct.Size)
            
            res["ResourcesNb"] = resources_nb
            res["ResourcesMeanEntropy"] = sum(resources_entropy)/len(resources_entropy) if resources_entropy else 0
            res["ResourcesMinEntropy"] = min(resources_entropy) if resources_entropy else 0
            res["ResourcesMaxEntropy"] = max(resources_entropy) if resources_entropy else 0
            res["ResourcesMeanSize"] = sum(resources_size)/len(resources_size) if resources_size else 0
            res["ResourcesMinSize"] = min(resources_size) if resources_size else 0
            res["ResourcesMaxSize"] = max(resources_size) if resources_size else 0
            
            # --- Sizes ---
            res["LoadConfigurationSize"] = self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size if hasattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') else 0
            res["VersionInformationSize"] = 0 # Simplified
            if hasattr(self.pe, 'VS_VERSIONINFO'): res["VersionInformationSize"] = 1
            
            self.results = res
            self.results["mitre_techniques"] = list(mitre_techniques)
            self.results["human_insights"] = self.get_human_insights()
            self.results["entropy"] = res["SectionsMaxEntropy"] # Consistent for score visualization
            
            return self.results

        except Exception as e:
            return {"error": str(e)}
        finally:
            if self.pe: self.pe.close()
