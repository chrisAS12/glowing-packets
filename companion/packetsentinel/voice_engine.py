"""
Offline microphone capture and speech-to-text for the SentinelWire voice airlock.

Audio never leaves the machine: capture uses PortAudio via `sounddevice`, and
transcription uses a locally cached faster-whisper model loaded with
`local_files_only=True`, so a missing model fails loudly instead of silently
downloading or falling back to a cloud recognizer.
"""

from __future__ import annotations

import importlib.util
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

    @property
    def ready(self) -> bool:
        return self.microphone_ready and self.transcriber_ready


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def get_model_dir(app_dir: Path) -> Path:
    return app_dir / "models" / "whisper"


def is_model_cached(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> bool:
    if not model_dir.exists():
        return False
    # huggingface_hub cache layout: models--Systran--faster-whisper-<name>/snapshots/<rev>/model.bin
    repo_dir = model_dir / f"models--Systran--faster-whisper-{model_name}"
    if any(repo_dir.glob("snapshots/*/model.bin")):
        return True
    if (model_dir / "model.bin").is_file():
        return True
    if (model_dir / model_name / "model.bin").is_file():
        return True
    return False


def check_voice_status(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> VoiceEngineStatus:
    mic_ready = _module_available("sounddevice") and _module_available("numpy")
    stt_installed = _module_available("faster_whisper")
    model_ready = stt_installed and is_model_cached(model_dir, model_name)

    if not mic_ready:
        detail = "Microphone capture needs 'sounddevice' and 'numpy'. " + VOICE_INSTALL_HINT
    elif not stt_installed:
        detail = "Offline speech engine (faster-whisper) is not installed. " + VOICE_INSTALL_HINT
    elif not model_ready:
        detail = f"Offline speech model '{model_name}' is not downloaded yet. " + VOICE_INSTALL_HINT
    else:
        detail = f"Offline engine ready: faster-whisper '{model_name}' on CPU (int8)."
    return VoiceEngineStatus(microphone_ready=mic_ready, transcriber_ready=model_ready, detail=detail)


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


def download_voice_model(model_dir: Path, model_name: str = DEFAULT_MODEL_NAME) -> Path:
    """One-time, explicit, online setup step. Never called while monitoring."""
    if not _module_available("faster_whisper"):
        raise VoiceEngineError("faster-whisper is not installed. Install it with: pip install -r requirements-voice.txt")
    from faster_whisper import WhisperModel

    model_dir.mkdir(parents=True, exist_ok=True)
    WhisperModel(model_name, device="cpu", compute_type="int8", download_root=str(model_dir))
    if not is_model_cached(model_dir, model_name):
        raise VoiceEngineError(f"Model download finished but '{model_name}' was not found in {model_dir}.")
    return model_dir
