"""Azure AI Foundry agent client wrapper.

This module provides a thin abstraction over the Azure AI Projects SDK
so the rest of the codebase does not depend directly on the SDK's internal
types.  The :class:`FoundryAgentClient` registers the M365 security agent
in an Azure AI Foundry project and manages the message/run lifecycle.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

MessageHandler = Callable[[str, str], str]
"""Type alias for a function that accepts (thread_id, user_message) -> reply."""


class FoundryAgentClient:
    """Thin wrapper around the Azure AI Projects agent SDK.

    Parameters
    ----------
    endpoint:
        The Azure AI Foundry project endpoint URL.
    api_key:
        API key or credential for the Foundry project.
    agent_name:
        Display name for the agent in the Foundry project.
    model_deployment:
        The model deployment name to use (e.g., ``gpt-4o``).
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        agent_name: str = "m365-security-agent",
        model_deployment: str = "gpt-4o",
    ) -> None:
        self._endpoint = endpoint
        self._api_key = api_key
        self._agent_name = agent_name
        self._model_deployment = model_deployment
        self._agent_id: Optional[str] = None
        self._client: Optional[Any] = None
        self._message_handler: Optional[MessageHandler] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def setup(self, message_handler: MessageHandler) -> None:
        """Initialise the Foundry SDK client and register the agent.

        Parameters
        ----------
        message_handler:
            Callable invoked when a message is received.  It receives
            ``(thread_id, user_message)`` and must return the agent's reply.
        """
        self._message_handler = message_handler
        try:
            from azure.ai.projects import AIProjectClient  # type: ignore[import]
            from azure.core.credentials import AzureKeyCredential  # type: ignore[import]

            self._client = AIProjectClient(
                endpoint=self._endpoint,
                credential=AzureKeyCredential(self._api_key),
            )
            self._agent_id = self._register_agent()
            logger.info(
                "Foundry agent '%s' registered with id '%s'",
                self._agent_name,
                self._agent_id,
            )
        except ImportError:
            logger.warning(
                "azure-ai-projects SDK not installed. "
                "Running in standalone (non-Foundry) mode."
            )

    def _register_agent(self) -> str:
        """Create or retrieve the agent in the Foundry project."""
        assert self._client is not None
        instructions = (
            "You are an M365 Security Agent. You monitor Microsoft 365 tenants "
            "for security posture issues, can autonomously apply baseline "
            "security configurations, and provide detailed security reports. "
            "Always be concise, precise, and security-focused in your responses."
        )
        agent = self._client.agents.create_agent(
            model=self._model_deployment,
            name=self._agent_name,
            instructions=instructions,
        )
        return agent.id

    def create_thread(self) -> str:
        """Create a new conversation thread and return its ID."""
        if self._client is None:
            import uuid
            return str(uuid.uuid4())
        thread = self._client.agents.create_thread()
        return thread.id

    def send_message(self, thread_id: str, content: str) -> str:
        """Send *content* to *thread_id* and return the agent's reply.

        When running outside Foundry (no SDK) the registered
        *message_handler* is called directly.
        """
        if self._client is None or self._agent_id is None:
            if self._message_handler:
                return self._message_handler(thread_id, content)
            return "Agent not initialised."

        self._client.agents.create_message(
            thread_id=thread_id,
            role="user",
            content=content,
        )
        run = self._client.agents.create_and_process_run(
            thread_id=thread_id,
            agent_id=self._agent_id,
        )
        messages = self._client.agents.list_messages(thread_id=thread_id)
        for msg in messages:
            if msg.role == "assistant" and msg.run_id == run.id:
                for part in msg.content:
                    if hasattr(part, "text"):
                        return part.text.value
        return ""

    def process_event(self, event: Dict[str, Any]) -> Optional[str]:
        """Process an incoming webhook event (e.g. from Teams / Copilot Studio).

        Returns the reply string, or ``None`` if the event is not a message.
        """
        message = event.get("text") or event.get("content")
        thread_id = event.get("threadId") or event.get("conversationId", "default")
        if not message:
            return None
        return self.send_message(thread_id, str(message))
