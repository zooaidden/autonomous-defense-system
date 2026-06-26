from agent_brain.services.os_topology_probe import build_dynamic_topology


def test_build_dynamic_topology_from_os_socket_snapshot():
    sockets = {
        "success": True,
        "result": {
            "backend": "ss",
            "sockets": [
                {
                    "protocol": "tcp",
                    "state": "ESTAB",
                    "local_address": "10.0.0.5:5173",
                    "peer_address": "10.0.0.10:8080",
                    "process": 'users:(("node",pid=123,fd=20))',
                }
            ],
        },
    }
    processes = {
        "success": True,
        "result": [
            {
                "pid": 123,
                "comm": "node",
                "command": "node vite",
            }
        ],
    }

    topology = build_dynamic_topology(
        sockets_envelope=sockets,
        processes_envelope=processes,
        generated_by="test",
    )

    assert topology["metadata"]["source"] == "os_probe"
    assert topology["metadata"]["dynamic"] is True
    assert len(topology["assets"]) >= 3
    assert len(topology["edges"]) >= 2
    graph = topology["knowledge_graph"]
    assert graph["nodes"]
    assert any(edge["type"] == "CONNECTS_TO" for edge in graph["edges"])
