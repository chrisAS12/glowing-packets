"""
Offline microphone capture and speech-to-text for the SentinelWire voice airlock.

Audio never leaves the machine: capture uses PortAudio via `sounddevice`, and
transcription uses a locally cached faster-whisper model loaded with
`local_files_only=True`, so a missing model fails loudly instead of silently
downloading or falling back to a cloud recognizer.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

SAMPLE_RATE_HZ = 16_000
MAX_RECORDING_SECONDS = 120
DEFAULT_MODEL_NAME = "base"
VOICE_INSTALL_HINT = "Run 'run.bat --setup-voice' (or 'python -m packetsentinel --setup-voice') once while online."


class VoiceEngineError(RuntimeError):
    """Raised with a user-readable message when capture or transcription cannot proceed."""


@dataclass(frozen=True)
class VoiceEngineStatus:
    microphone_ready: bool
    transcriber_ready: bool
    detail: str
    stt_installed: bool = False
    model_cached: bool = False
    windows_dictation_available: bool = False
    model_incomplete: bool = False

    @property
    def ready(self) -> bool:
        return self.microphone_ready and self.transcriber_ready


def is_windows_dictation_available() -> bool:
    """Checks whether Windows native speech recognition / Dictation (Win + H) is available on the OS."""
    if sys.platform != "win32":
        return False
    try:
        import win32com.client

        win32com.client.Dispatch("SAPI.SpVoice")
        return True
    except Exception:
        # Win + H is built into Windows 10/11 even if pywin32 is uninstalled
        return True


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def get_model_dir(app_dir: Path) -> Path:
    return app_dir / "models" / "whisper"


REQUIRED_MODEL_FILES = ("model.bin", "config.json")


def _is_directory_complete_model(directory: Path) -> bool:
    """Verifies that a directory has all essential files to run offline without network."""
    if not directory.is_dir():
        return False
    for req_name in REQUIRED_MODEL_FILES:
        target = directory / req_name
        if not target.is_file():
            return False
        try:
            if target.stat().st_size == 0:
                return False
        except Exception:
            return False
        if req_name == "config.json":
            try:
                import json

                parsed = json.loads(target.read_text(encoding="utf-8"))
                if not isinstance(parsed, dict):
                    return False
            except Exception:
                return False

    has_vocab = False
    for vf in ("vocabulary.txt", "vocabulary.json", "tokenizer.json"):
        vp = directory / vf
        if vp.is_file():
            try:
                if vp.stat().st_size > 0:
                    has_vocab = True
                    break
            except Exception:
                continue
    return has_vocab


def get_active_snapshot_dir(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> Optional[Path]:
    """Resolves the active HuggingFace Hub snapshot directory for faster-whisper."""
    repo_dir = model_dir / f"models--Systran--faster-whisper-{model_name}"
    snapshots_dir = repo_dir / "snapshots"
    if not snapshots_dir.is_dir():
        return None
    refs_main = repo_dir / "refs" / "main"
    if refs_main.is_file():
        try:
            commit_hash = refs_main.read_text(encoding="utf-8").strip()
            active_snap = snapshots_dir / commit_hash
            if active_snap.is_dir():
                return active_snap
        except Exception:
            pass
    snaps = [s for s in snapshots_dir.iterdir() if s.is_dir()]
    if snaps:
        snaps.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        return snaps[0]
    return None


def is_snapshot_incomplete(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> bool:
    """Returns True if a model cache directory exists locally but is missing required files (e.g. config.json)."""
    if is_model_cached(model_dir, model_name):
        return False
    repo_dir = model_dir / f"models--Systran--faster-whisper-{model_name}"
    snapshots_dir = repo_dir / "snapshots"
    if snapshots_dir.is_dir():
        for snap in snapshots_dir.iterdir():
            if snap.is_dir():
                return True
    if (model_dir / model_name).is_dir() or (model_dir / "model.bin").is_file():
        return True
    return False


def is_model_cached(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> bool:
    """Checks whether the offline speech model is fully downloaded and cached locally."""
    if not model_dir.exists():
        return False
    # 1. HuggingFace Hub snapshot directory layout:
    # First check the active snapshot pointed to by refs/main
    active_snap = get_active_snapshot_dir(model_dir, model_name)
    if active_snap is not None and _is_directory_complete_model(active_snap):
        return True
    repo_dir = model_dir / f"models--Systran--faster-whisper-{model_name}"
    snapshots_dir = repo_dir / "snapshots"
    if snapshots_dir.is_dir():
        for snap in snapshots_dir.iterdir():
            if snap.is_dir() and _is_directory_complete_model(snap):
                return True
    # 2. Direct directory layout (standalone / air-gapped bundle):
    if _is_directory_complete_model(model_dir):
        return True
    if _is_directory_complete_model(model_dir / model_name):
        return True
    return False


def check_voice_status(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> VoiceEngineStatus:
    mic_ready = _module_available("sounddevice") and _module_available("numpy")
    stt_installed = _module_available("faster_whisper")
    cached = is_model_cached(model_dir, model_name) if stt_installed else False
    incomplete = is_snapshot_incomplete(model_dir, model_name) if stt_installed else False
    model_ready = stt_installed and cached
    win_dictation = is_windows_dictation_available()

    if not mic_ready:
        detail = "Microphone capture needs 'sounddevice' and 'numpy'. " + VOICE_INSTALL_HINT
    elif not stt_installed:
        detail = "Offline speech engine (faster-whisper) is not installed. " + VOICE_INSTALL_HINT
    elif not model_ready:
        if incomplete:
            detail = (
                f"Offline speech model '{model_name}' snapshot is incomplete (missing config.json). "
                "Press Win + H to dictate, or click 'Repair Voice Engine' to fix."
            )
        else:
            detail = f"Offline speech model '{model_name}' is not downloaded yet. " + VOICE_INSTALL_HINT
    else:
        detail = f"Offline engine ready: faster-whisper '{model_name}' on CPU (int8)."
    return VoiceEngineStatus(
        microphone_ready=mic_ready,
        transcriber_ready=model_ready,
        detail=detail,
        stt_installed=stt_installed,
        model_cached=cached,
        windows_dictation_available=win_dictation,
        model_incomplete=incomplete,
    )


class MicrophoneRecorder:
    """Records mono 16 kHz audio until stop() is called, silence is detected, or the safety cap is reached."""

    def __init__(
        self,
        max_seconds: int = MAX_RECORDING_SECONDS,
        silence_timeout_seconds: float = 1.8,
    ) -> None:
        self._max_frames = max_seconds * SAMPLE_RATE_HZ
        self.silence_timeout_seconds = silence_timeout_seconds
        self._chunks: List[Any] = []
        self._frames = 0
        self._lock = threading.Lock()
        self._stream: Optional[Any] = None
        self.hit_time_limit = False
        self.hit_silence_limit = False
        self._speech_detected = False
        self._last_speech_time = 0.0

    @property
    def is_recording(self) -> bool:
        return self._stream is not None

    def start(self) -> None:
        try:
            import sounddevice as sd
        except ImportError as exc:
            raise VoiceEngineError("Microphone capture needs 'sounddevice'. " + VOICE_INSTALL_HINT) from exc
        except Exception as exc:
            raise VoiceEngineError(f"Could not load audio library: {exc}") from exc

        self._chunks = []
        self._frames = 0
        self.hit_time_limit = False
        self.hit_silence_limit = False
        self._speech_detected = False
        self._last_speech_time = 0.0

        # Pre-flight check: verify an input device exists
        try:
            default_device = getattr(sd, "default", None)
            if default_device is not None and hasattr(default_device, "device"):
                dev_pair = default_device.device
                dev_idx = dev_pair[0] if isinstance(dev_pair, (list, tuple)) else dev_pair
                if dev_idx is not None and dev_idx < 0:
                    query_fn = getattr(sd, "query_devices", None)
                    if callable(query_fn):
                        devs = query_fn()
                        has_input = any(d.get("max_input_channels", 0) > 0 for d in devs if isinstance(d, dict))
                        if not has_input:
                            raise VoiceEngineError("No microphone or audio input device found on this system.")
        except VoiceEngineError:
            raise
        except Exception:
            pass

        try:
            self._stream = sd.InputStream(
                samplerate=SAMPLE_RATE_HZ, channels=1, dtype="float32", callback=self._on_audio
            )
            self._stream.start()
        except VoiceEngineError:
            self._stream = None
            raise
        except Exception as exc:
            self._stream = None
            raise VoiceEngineError(f"Could not open the microphone: {exc}") from exc

    def _on_audio(self, indata: Any, frames: int, _time_info: Any, _status: Any) -> None:
        try:
            import numpy as np

            with self._lock:
                if self._frames >= self._max_frames:
                    self.hit_time_limit = True
                    return
                self._chunks.append(indata.copy())
                self._frames += frames

                if indata is not None and len(indata) > 0:
                    try:
                        rms = float(np.sqrt(np.mean(indata**2)))
                    except Exception:
                        rms = 0.0
                    now = time.time()
                    if rms > 0.015:
                        self._speech_detected = True
                        self._last_speech_time = now
                    elif self._speech_detected and (now - self._last_speech_time) > self.silence_timeout_seconds:
                        self.hit_silence_limit = True
        except Exception:
            # Audio callback must never raise into PortAudio native thread
            pass

    def stop(self) -> Any:
        """Stop capture and return a 1-D float32 numpy array (may be empty)."""
        stream, self._stream = self._stream, None
        if stream is not None:
            try:
                stream.stop()
            except Exception:
                pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass
        with self._lock:
            if not self._chunks:
                try:
                    import numpy as np

                    return np.zeros(0, dtype=np.float32)
                except Exception:
                    return []
            try:
                import numpy as np

                return np.concatenate(self._chunks, axis=0).reshape(-1).astype(np.float32)
            except Exception as exc:
                raise VoiceEngineError(f"Failed to assemble captured audio: {exc}") from exc


class OfflineTranscriber:
    """Lazily loads a locally cached faster-whisper model and transcribes numpy audio."""

    def __init__(self, model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> None:
        self._model_dir = model_dir
        self._model_name = model_name
        self._model: Optional[Any] = None
        self._load_lock = threading.Lock()

    def _load(self) -> Any:
        with self._load_lock:
            if self._model is not None:
                return self._model
            status = check_voice_status(self._model_dir, self._model_name)
            if not status.transcriber_ready:
                raise VoiceEngineError(status.detail)
            try:
                from faster_whisper import WhisperModel
            except ImportError as exc:
                raise VoiceEngineError("faster-whisper is not installed. " + VOICE_INSTALL_HINT) from exc
            except Exception as exc:
                raise VoiceEngineError(f"Could not load faster-whisper library: {exc}. " + VOICE_INSTALL_HINT) from exc

            try:
                self._model = WhisperModel(
                    self._model_name,
                    device="cpu",
                    compute_type="int8",
                    download_root=str(self._model_dir),
                    local_files_only=True,
                )
            except Exception as exc:
                err_text = str(exc)
                if "incomplete" in err_text.lower() or "config.json" in err_text.lower():
                    raise VoiceEngineError(
                        f"Offline speech model '{self._model_name}' snapshot is incomplete (missing config.json). "
                        "Click 'Repair Voice Engine' to fix in 1-click or press Win + H to dictate."
                    ) from exc
                raise VoiceEngineError(
                    f"Failed to load offline Whisper model '{self._model_name}': {exc}. " + VOICE_INSTALL_HINT
                ) from exc
            return self._model

    def transcribe(self, audio: Any) -> str:
        if audio is None or len(audio) < SAMPLE_RATE_HZ // 4:
            raise VoiceEngineError("No speech captured (recording shorter than 0.25 s).")
        model = self._load()
        try:
            segments, _info = model.transcribe(audio, beam_size=1, vad_filter=True)
            text = " ".join(seg.text.strip() for seg in segments).strip()
        except VoiceEngineError:
            raise
        except Exception as exc:
            raise VoiceEngineError(f"Transcription failed: {exc}") from exc

        if not text:
            raise VoiceEngineError("No speech detected in the recording. Check your microphone input level.")
        return text


def _download_file_direct(url: str, destination: Path) -> bool:
    """Safely and atomically downloads a single file over HTTPS using TLS 1.2+."""
    import ssl
    import urllib.request

    temp_dest = destination.with_suffix(destination.suffix + ".ps_tmp")
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "PacketSentinel-VoiceEngine/1.0"},
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(req, context=ctx, timeout=20.0) as resp:
            content = resp.read()
            if not content:
                return False
            temp_dest.write_bytes(content)
        temp_dest.replace(destination)
        return True
    except Exception:
        if temp_dest.exists():
            try:
                temp_dest.unlink()
            except Exception:
                pass
        return False


def _ensure_snapshot_files_complete(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> None:
    """
    Ensures that config.json and other essential model files exist and are valid.
    Specifically repairs missing config.json in existing snapshots.
    """
    if is_model_cached(model_dir, model_name):
        return

    repo_id = f"Systran/faster-whisper-{model_name}"

    try:
        from huggingface_hub import hf_hub_download

        for fname in ("config.json", "vocabulary.txt", "tokenizer.json"):
            try:
                hf_hub_download(repo_id=repo_id, filename=fname, cache_dir=str(model_dir))
            except Exception:
                pass
    except Exception:
        pass

    active_snap = get_active_snapshot_dir(model_dir, model_name)
    targets = [active_snap] if active_snap is not None else []
    repo_dir = model_dir / f"models--Systran--faster-whisper-{model_name}"
    snapshots_dir = repo_dir / "snapshots"
    if snapshots_dir.is_dir():
        for s in snapshots_dir.iterdir():
            if s.is_dir() and s not in targets:
                targets.append(s)

    if not targets:
        direct_target = model_dir / model_name
        direct_target.mkdir(parents=True, exist_ok=True)
        targets.append(direct_target)

    for target_dir in targets:
        cfg_file = target_dir / "config.json"
        is_cfg_ok = False
        if cfg_file.is_file() and cfg_file.stat().st_size > 0:
            try:
                import json

                parsed = json.loads(cfg_file.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    is_cfg_ok = True
            except Exception:
                is_cfg_ok = False

        if not is_cfg_ok:
            _download_file_direct(
                url=f"https://huggingface.co/{repo_id}/raw/main/config.json",
                destination=cfg_file,
            )


def download_offline_model(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> Path:
    """
    One-time, explicit, online setup step. Downloads and atomically validates
    the offline faster-whisper model. Never called while monitoring.
    """
    if not _module_available("faster_whisper"):
        raise VoiceEngineError("faster-whisper is not installed. Install it with: pip install -r requirements-voice.txt")
    from faster_whisper import WhisperModel

    model_dir.mkdir(parents=True, exist_ok=True)
    try:
        WhisperModel(model_name, device="cpu", compute_type="int8", download_root=str(model_dir))
    except Exception as exc:
        _ensure_snapshot_files_complete(model_dir, model_name)
        if not is_model_cached(model_dir, model_name):
            raise VoiceEngineError(f"Model download failed for '{model_name}': {exc}") from exc

    _ensure_snapshot_files_complete(model_dir, model_name)

    if not is_model_cached(model_dir, model_name):
        raise VoiceEngineError(
            f"Model download finished but '{model_name}' was not valid in {model_dir}. "
            "Essential files (config.json, model.bin, vocabulary) are incomplete."
        )
    return model_dir


# Backward-compatible alias
download_voice_model = download_offline_model


def repair_offline_model(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> bool:
    """
    1-click self-healing repair: Fixes missing or incomplete snapshot files (e.g. config.json).
    Returns True if model is cached and valid after repair.
    """
    try:
        _ensure_snapshot_files_complete(model_dir, model_name)
        if is_model_cached(model_dir, model_name):
            return True
        download_offline_model(model_dir, model_name)
        return is_model_cached(model_dir, model_name)
    except Exception:
        return is_model_cached(model_dir, model_name)
