# -*- coding: utf-8 -*-
import os
import asyncio
import json
import logging
from typing import List, Dict, Any, Set, Tuple

import google.generativeai as genai

# Configura logging para que los mensajes vayan a stdout (visible en Docker)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class GeminiDependencyAnalyzer:
    """
    Analiza un proyecto de software archivo por archivo usando la API de Gemini
    para extraer dependencias de terceros de forma precisa.
    """

    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError("La clave de API de Gemini no puede estar vacía.")
        logger.info("🔑 Configurando Gemini API...")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash-latest')
        self.generation_config = {
            "response_mime_type": "application/json",
            "temperature": 0.0,
        }
        self.prompt_template = """
Actúa como un analista experto en seguridad de software y gestión de dependencias. Tu tarea es analizar el contenido de un único archivo de código fuente y extraer únicamente las dependencias de LIBRERÍAS DE TERCEROS.

**Reglas Estrictas:**
1. **IDENTIFICA** solo librerías externas que un desarrollador necesitaría instalar (ej: flask, react, numpy, log4j, gson).
2. **IGNORA** librerías estándar del lenguaje (ej: 'os', 'sys' en Python; 'fs', 'http' en Node.js; 'stdio.h' en C; 'java.util', 'java.io' en Java).
3. **IGNORA** importaciones relativas o locales del proyecto (ej: './utils', '../components', 'com.miempresa.modulo').
4. **DEVUELVE** el nombre canónico de la dependencia, el que se usaría en `pip`, `npm`, `mvn`, etc. (ej: `org.apache.commons.lang3` -> `commons-lang3`).
5. **RESPONDE** siempre con un objeto JSON válido con la siguiente estructura: `{{"dependencies": [{{"name": "nombre-dependencia", "version": null, "type": "runtime"}}]}}`.
6. Si NO se encuentran dependencias de terceros en el archivo, devuelve una lista vacía: `{{"dependencies": []}}`.

**Archivo a analizar:** `{filename}`

**Contenido del archivo:**
{content}
"""


    def _is_relevant_file(self, filename: str) -> bool:
        source_code_extensions = {
            '.py', '.java', '.js', '.ts', '.tsx', '.go', '.rb', '.php', '.rs', '.cs',
            '.c', '.cpp', '.h', '.hpp', '.m', '.swift', '.kt', '.scala'
        }
        config_files = {
            'pom.xml', 'build.gradle', 'package.json', 'requirements.txt',
            'pyproject.toml', 'go.mod', 'gemfile'
        }

        name_lower = filename.lower()

        if name_lower in config_files:
            return True

        _, ext = os.path.splitext(name_lower)
        return ext in source_code_extensions

    async def _analyze_file(self, file_path: str, filename: str) -> List[Dict[str, Any]]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if not content or len(content) > 500_000:
                logger.warning(f"⚠ El archivo '{filename}' está vacío o es demasiado grande. Saltando.")
                return []

            logger.info(f"🔍 Analizando archivo: {filename}")

            prompt = self.prompt_template.format(filename=filename, content=content)
            response = await self.model.generate_content_async(
                prompt,
                generation_config=self.generation_config
            )

            logger.debug(f"📥 Respuesta cruda recibida de Gemini para {filename}: {response.text[:500]}...")

            try:
                result = json.loads(response.text)
                if 'dependencies' in result and isinstance(result['dependencies'], list):
                    return result['dependencies']
                else:
                    logger.warning(f"⚠ Respuesta sin campo 'dependencies' válido en {filename}.")
                    return []
            except json.JSONDecodeError as jde:
                logger.error(f"❌ Error decodificando JSON para {filename}: {str(jde)}")
                logger.error(f"❌ Respuesta cruda: {response.text}")
                return []

        except Exception as e:
            logger.exception(f"❌ Error al analizar el archivo '{filename}': {str(e)}")
            return []

    async def analyze_project(self, directory_path: str) -> List[Dict[str, Any]]:
        tasks = []
        for root, _, files in os.walk(directory_path):
            for filename in files:
                if self._is_relevant_file(filename):
                    file_path = os.path.join(root, filename)
                    tasks.append(self._analyze_file(file_path, filename))

        logger.info(f"✅ Se van a analizar {len(tasks)} archivos relevantes con Gemini...")

        results_from_files = await asyncio.gather(*tasks)

        unique_dependencies: Set[Tuple[str, Any, str]] = set()
        for result_list in results_from_files:
            for dep in result_list:
                name = dep.get("name")
                if name:
                    unique_dependencies.add((
                        name,
                        dep.get("version"),
                        dep.get("type", "runtime")
                    ))

        final_list = [
            {"name": name, "version": version, "type": type_}
            for name, version, type_ in sorted(unique_dependencies)
        ]

        logger.info(f"✅ Análisis completado. Se encontraron {len(final_list)} dependencias únicas.")
        logger.debug(f"📋 Dependencias encontradas: {json.dumps(final_list, indent=2)}")
        return final_list
