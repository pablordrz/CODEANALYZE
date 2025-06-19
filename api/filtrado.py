# -*- coding: utf-8 -*-
import os
import re
from typing import List, Dict, Any, Tuple, Optional

class StaticDependencyAnalyzer:
    """
    Analiza estáticamente los archivos de un directorio para extraer dependencias
    basándose en palabras clave y extensiones de archivo.
    """
    def __init__(self):
        self.import_dict = {
            "import / from": [".py", ".pyc", ".pyo", ".pyd"],
            "#include": [".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".m"],
            "using": [".cs", ".jl"],
            "require / require_once / include / import": [".js", ".mjs", ".cjs", ".ts", ".tsx", ".rb", ".pl", ".pm", ".t", ".php", ".phtml", ".php3", ".php4", ".php5", ".phps"],
            "source / .": [".sh", ".ps1", ".psm1", ".psd1", ".bat", ".cmd"],
            "USE / IMPORT": [".sql", ".pls", ".pck", ".pkb", ".pks", ".f", ".f90", ".for"],
            "extends / class_name": [".gd"],
            "-include / use / import": [".ex", ".exs", ".erl", ".hrl", ".lisp", ".lsp", ".cl", ".clj", ".cljs", ".cljc"],
            "library / use / 'include": [".vhd", ".vhdl", ".v", ".vh"]
        }
        # Mapeo de extensiones a sus palabras clave para una búsqueda más rápida
        self.extension_to_keywords = {
            ext: keywords for keywords, exts in self.import_dict.items() for ext in exts
        }

    def _parse_dependency_from_line(self, line: str) -> Optional[str]:
        """
        Extrae el nombre de la dependencia de una línea de código.
        """
        line = line.strip()
        
        # Python: import flask, from flask import ...
        if line.startswith("import ") or line.startswith("from "):
            return line.split()[1].split('.')[0]
            
        # JS/PHP/Ruby: require('express'), import ... from 'react'
        match = re.search(r"(?:require|import)\s*\(?\s*['\"]([^'\"]+)['\"]", line)
        if match:
            return match.group(1).split('/')[0] # Para casos como 'react-dom/client'

        # C/C++: #include <stdio.h>
        match = re.search(r'#include\s*[<"]([^>"]+)[>"]', line)
        if match:
            # Omitimos extensiones comunes para obtener el nombre de la librería
            return os.path.splitext(match.group(1))[0]

        # C#: using System.Text;
        if line.startswith("using "):
            parts = line.split()
            if len(parts) > 1:
                return parts[1].split('.')[0] # Devuelve la raíz del namespace

        return None

    def _find_deps_in_file(self, file_path: str, keywords: str) -> List[str]:
        """
        Busca dependencias en un único archivo.
        """
        dependencies = set()
        keyword_tuple = tuple(k.strip() for k in keywords.replace(" / ", "/").split("/"))
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_strip = line.strip()
                    if any(line_strip.startswith(p) for p in keyword_tuple):
                        dep_name = self._parse_dependency_from_line(line_strip)
                        if dep_name:
                            dependencies.add(dep_name)
        except (IOError, UnicodeDecodeError) as e:
            print(f"Advertencia: No se pudo leer el archivo '{os.path.basename(file_path)}': {e}")
        
        return list(dependencies)

    def analizar_dependencias(self, ruta_carpeta: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Función principal que recorre un directorio y analiza los archivos.

        Args:
            ruta_carpeta: La ruta al directorio del proyecto a analizar.

        Returns:
            Un tuple con:
            - Una lista de diccionarios de dependencias encontradas.
            - Una lista de nombres de archivo que no pudieron ser procesados.
        """
        dependencias_encontradas = set()
        archivos_no_identificados = []

        for root, _, files in os.walk(ruta_carpeta):
            for filename in files:
                file_ext = os.path.splitext(filename)[1]
                
                if file_ext in self.extension_to_keywords:
                    keywords = self.extension_to_keywords[file_ext]
                    ruta_completa = os.path.join(root, filename)
                    deps_from_file = self._find_deps_in_file(ruta_completa, keywords)
                    dependencias_encontradas.update(deps_from_file)
                else:
                    # Ignoramos archivos comunes que no contienen dependencias
                    if file_ext not in ['.md', '.txt', '.json', '.xml', '.yml', '.yaml', '.gitignore', '']:
                        archivos_no_identificados.append(filename)
        
        # Formateamos el resultado como lo necesita la API
        resultado_formateado = [
            {"name": name, "version": None, "type": "runtime"} for name in dependencias_encontradas
        ]

        return resultado_formateado, list(set(archivos_no_identificados))