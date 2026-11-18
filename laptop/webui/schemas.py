"""Pydantic-схемы запросов API."""

from pydantic import BaseModel, Field


class LabelRequest(BaseModel):
    label: str | None = None
    note: str | None = None


class BulkLabelRequest(BaseModel):
    ids: list[int] = Field(min_length=1)
    label: str | None = None
    note: str | None = None


class ReplayRequest(BaseModel):
    mode: str = "verbatim"  # verbatim | template | npc


class CustomReplayRequest(BaseModel):
    """Отправка изменённого payload (клонер) на указанную цель."""
    host: str = Field(min_length=1)
    port: int = Field(gt=0, le=65535)
    payload: str  # latin-1 текст payload


class CloneRequest(BaseModel):
    host: str | None = None
    port: int | None = Field(default=None, gt=0, le=65535)


class NpcAutoprobeRequest(BaseModel):
    """Переключатель автопробы новых детектов на NPC."""
    enabled: bool
