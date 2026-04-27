import logging
logger = logging.getLogger(__name__)

def execute(params: dict, context: dict) -> str:
    code = params.get("code", "")
    if not code:
        return "skipped: no code"
    # Execute in a sandboxed environment with limited builtins
    sandbox_globals = {"__builtins__": {"print": print, "len": len, "str": str, "int": int}}
    output = []
    import io, contextlib
    f = io.StringIO()
    with contextlib.redirect_stdout(f):
        try:
            exec(code, sandbox_globals, {"context": context})
        except Exception as e:
            return f"error: {e}"
    return f.getvalue() or "executed"
