import os
import aiohttp
import asyncio
import json
import re
from typing import List, Dict, Any

class DeepSeekDependencyExtractor:
    def __init__(self, api_token: str):
        self.api_token = api_token
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.base_url = "https://llm.chutes.ai/v1/chat/completions"
        self.model = "deepseek-ai/DeepSeek-V3-0324"
        self.max_tokens = 4096
        self.temperature = 0.1

    def extract_imports_from_file(self, file_path: str) -> List[str]:
        """Extrae los imports directamente del archivo (análisis estático)"""
        imports = []
        import_pattern = re.compile(r'^(?:\s*)?(?:import|from)\s+([\w\.]+)', re.MULTILINE)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                matches = import_pattern.findall(content)
                for match in matches:
                    imports.append(match.split('.')[0])
        except Exception as e:
            print(f"❌ Error leyendo {file_path}: {e}")
        
        return imports

    async def collect_all_possible_dependencies(self, directory_path: str) -> List[str]:
        all_imports = set()
        
        for root, _, files in os.walk(directory_path):
            for filename in files:
                if filename.endswith('.py'):
                    file_path = os.path.join(root, filename)
                    imports = self.extract_imports_from_file(file_path)
                    all_imports.update(imports)
        
        return list(all_imports)

    async def analyze_project_dependencies(self, directory_path: str) -> List[Dict[str, Any]]:
        preliminary_imports = await self.collect_all_possible_dependencies(directory_path)
        
        prompt = f"""
Se ha analizado el siguiente proyecto Python. Aquí están los módulos importados:

{preliminary_imports}

Tu tarea:
- Identifica cuáles de estos son dependencias externas (librerías de terceros).
- Elimina módulos estándar de Python.
- Elimina módulos internos o locales.
- Devuelve un JSON válido con esta estructura:

{{
    "dependencies": [
        {{
            "name": "nombre_de_dependencia",
            "version": null,
            "type": "runtime"
        }}
    ]
}}

Responde SOLO con el JSON.
"""
        
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "Eres un experto en gestión de dependencias de proyectos Python."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.base_url, headers=self.headers, json=body) as response:
                    if response.status == 200:
                        response_data = await response.json()
                        content = response_data['choices'][0]['message']['content']
                        content = content.strip()
                        if content.startswith('```json'):
                            content = content[7:]
                        if content.endswith('```'):
                            content = content[:-3]
                        content = content.strip()
                        
                        try:
                            result = json.loads(content)
                            return result.get('dependencies', [])
                        except json.JSONDecodeError as e:
                            print(f"❌ Error decodificando JSON: {e}")
                            return []
                    else:
                        print(f"❌ Error en la API. Código: {response.status}")
                        return []
        except Exception as e:
            print(f"❌ Error procesando petición IA: {e}")
            return []

    # Este método queda para compatibilidad si lo quieres seguir usando
    async def extract_dependencies_from_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        return await self.analyze_project_dependencies(directory_path)
