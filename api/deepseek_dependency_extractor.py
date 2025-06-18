import os
import aiohttp
import asyncio
import json
import tempfile
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

    def _create_file_analysis_prompt(self, file_content: str, filename: str) -> str:
        """Crea el prompt para que la IA identifique el tipo de archivo y extraiga dependencias"""
        return f"""Eres un experto en análisis de código que puede identificar cualquier tipo de archivo y extraer dependencias.

**Archivo:** {filename}

**Contenido del archivo:**
```
{file_content}
```

**Tu tarea:**
1. **IDENTIFICA** automáticamente qué tipo de archivo es este basándote en:
   - El contenido del archivo
   - La extensión del archivo (si es útil)
   - La sintaxis y patrones del código
   - Palabras clave específicas del lenguaje
   - Estructura del archivo

2. **EXTRAE** todas las dependencias externas si es un archivo de código, configuración o definición de dependencias.

**Criterios para dependencias:**
- Incluye: librerías de terceros, paquetes externos, frameworks, módulos no estándar
- Excluye: librerías estándar del lenguaje, módulos internos del proyecto, funciones built-in
- Si es un archivo de configuración de dependencias (como package.json, requirements.txt, etc.), extrae TODAS las dependencias listadas
- Si es código fuente, extrae las importaciones/requires/includes de librerías externas

**Formato de respuesta:**
Responde ÚNICAMENTE con un JSON válido en este formato:
{{
    "file_type": "tipo_de_archivo_identificado",
    "language": "lenguaje_programacion",
    "is_code_file": true/false,
    "dependencies": [
        {{
            "name": "nombre_de_la_dependencia",
            "version": "version_si_esta_especificada_o_null",
            "type": "tipo_de_dependencia"
        }}
    ]
}}

**IMPORTANTE:**
- Si no puedes identificar el tipo de archivo, usa "Unknown" pero aún intenta extraer dependencias si ves patrones reconocibles
- Si no hay dependencias externas, devuelve un array vacío en dependencies
- NO limites tu análisis a lenguajes específicos - analiza CUALQUIER tipo de archivo
- Sé conservador: si no estás seguro de que algo es una dependencia externa, no la incluyas

Responde SOLO con el JSON, sin explicaciones adicionales."""

    async def _analyze_file_with_ai(self, file_content: str, filename: str) -> Dict[str, Any]:
        """Analiza un archivo con IA para identificar tipo y extraer dependencias"""
        prompt = self._create_file_analysis_prompt(file_content, filename)
        
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Eres un experto en análisis de código que puede identificar cualquier tipo de archivo y lenguaje de programación. Respondes únicamente con JSON válido."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.base_url,
                    headers=self.headers,
                    json=body
                ) as response:
                    if response.status == 200:
                        response_data = await response.json()
                        content = response_data['choices'][0]['message']['content']
                        
                        # Limpiar el contenido y extraer el JSON
                        content = content.strip()
                        if content.startswith('```json'):
                            content = content[7:]
                        if content.endswith('```'):
                            content = content[:-3]
                        content = content.strip()
                        
                        try:
                            result = json.loads(content)
                            return result
                        except json.JSONDecodeError as e:
                            print(f"❌ Error decodificando JSON para {filename}: {e}")
                            return {
                                "file_type": "Unknown",
                                "language": "Unknown", 
                                "is_code_file": False,
                                "dependencies": []
                            }
                    else:
                        print(f"❌ Error en la API para {filename}. Código: {response.status}")
                        return {
                            "file_type": "Unknown",
                            "language": "Unknown",
                            "is_code_file": False, 
                            "dependencies": []
                        }
        except Exception as e:
            print(f"❌ Error procesando {filename}: {e}")
            return {
                "file_type": "Unknown",
                "language": "Unknown",
                "is_code_file": False,
                "dependencies": []
            }

    async def extract_dependencies_from_file(self, file_path: str) -> Dict[str, Any]:
        """Extrae dependencias de un archivo específico usando IA"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if len(content.strip()) == 0:
                return {"dependencies": []}
            
            filename = os.path.basename(file_path)
            analysis = await self._analyze_file_with_ai(content, filename)
            
            return {"dependencies": analysis.get('dependencies', [])}
            
        except Exception as e:
            print(f"❌ Error procesando archivo {file_path}: {e}")
            return {"dependencies": []}

    async def extract_dependencies_from_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """Extrae dependencias de todos los archivos en un directorio"""
        all_dependencies = []
        
        for root, _, files in os.walk(directory_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                # Saltar archivos muy grandes
                try:
                    if os.path.getsize(file_path) > 1024 * 1024:  # 1MB
                        continue
                except:
                    continue
                
                result = await self.extract_dependencies_from_file(file_path)
                all_dependencies.extend(result["dependencies"])
                
                # Pausa para no sobrecargar la API
                await asyncio.sleep(0.1)
        
        # Eliminar duplicados
        unique_dependencies = []
        seen = set()
        
        for dep in all_dependencies:
            name = dep.get('name', '')
            version = dep.get('version', '')
            key = (name, version)
            
            if key not in seen and name:
                seen.add(key)
                unique_dependencies.append(dep)
        
        return unique_dependencies

