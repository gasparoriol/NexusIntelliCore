# Plan de mitigación de la evaluación técnica crítica

**Fecha de elaboración:** 2026-08-16  
**Documento de origen:** [EVALUACION_TECNICA_CRITICA_NEXUSINTELLICORE.md](../EVALUACION_TECNICA_CRITICA_NEXUSINTELLICORE.md)  
**Ámbito:** siete debilidades y cuatro riesgos concretos identificados en la evaluación

## Objetivo

Convertir las debilidades detectadas en cambios pequeños, verificables y ordenados por riesgo. El objetivo no es reducir líneas por sí mismo, sino limitar el radio de impacto, hacer obligatorias las garantías de privacidad, aumentar la calidad de señal y volver explícita la operación.

## Artefactos

| Artefacto                                                                                | Punto tratado                             | Prioridad   |
| ---------------------------------------------------------------------------------------- | ----------------------------------------- | ----------- |
| [00_LINEA_BASE_Y_ROADMAP.md](00_LINEA_BASE_Y_ROADMAP.md)                                 | Evidencia, dependencias, fases y gobierno | Marco común |
| [01_DESCENTRALIZACION_DEL_DESPACHO.md](01_DESCENTRALIZACION_DEL_DESPACHO.md)             | Núcleo de despacho centralizado           | P0          |
| [02_PRIVACIDAD_ESTRUCTURAL.md](02_PRIVACIDAD_ESTRUCTURAL.md)                             | Privacidad manual y módulo sobrecargado   | P0          |
| [03_CALIDAD_DEL_GRAFO_DE_DEPENDENCIAS.md](03_CALIDAD_DEL_GRAFO_DE_DEPENDENCIAS.md)       | Evidencia arquitectónica ruidosa          | P1          |
| [04_CALIDAD_DE_LA_AUDITORIA_DE_SEGURIDAD.md](04_CALIDAD_DE_LA_AUDITORIA_DE_SEGURIDAD.md) | Auditoría con baja precisión              | P0          |
| [05_GOBIERNO_DE_UNSAFE.md](05_GOBIERNO_DE_UNSAFE.md)                                     | Superficie `unsafe` distribuida           | P1          |
| [06_LIMITES_Y_OPERABILIDAD.md](06_LIMITES_Y_OPERABILIDAD.md)                             | Métricas y límites implícitos             | P1          |
| [07_SINCRONIZACION_DOCUMENTAL.md](07_SINCRONIZACION_DOCUMENTAL.md)                       | Estado y producto desincronizados         | P2          |

## Principios de ejecución

1. No usar tamaño de archivo como criterio de éxito; medir responsabilidades, contratos y radio de cambio.
2. No convertir conteos brutos de auditoría en gates hasta corregir clasificación y duplicados.
3. Mantener compatibilidad MCP y defaults actuales salvo decisión explícita y documentada.
4. Añadir una prueba de caracterización antes de mover una frontera crítica.
5. Introducir un único cambio arquitectónico por PR y conservar una ruta de rollback.
6. No declarar cerrado un punto por documentación: debe cumplirse su criterio de salida ejecutable.

## Lectura recomendada

Comenzar por la línea base. Después ejecutar los planes 04 y 02, que corrigen respectivamente la confianza en la evidencia y la garantía transversal más sensible. Los planes 01 y 06 consolidan las fronteras arquitectónica y operativa. Los planes 03, 05 y 07 se apoyan en esas bases.
