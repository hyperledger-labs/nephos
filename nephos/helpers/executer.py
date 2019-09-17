from nephos.helpers.misc import execute

# Class to execute K8S commands
# TODO: We might wish to set the container at the execution level?
class Executer:
    def __init__(self, pod, namespace, container=""):
        """Executer creates a K8S pod object capable of:
        1) Execute commands,
        2) Return logs.

        Args:
            pod (str): Pod to bind to.
            namespace (str): Name of namespace.
            container (str): Container to bind to.
        """
        extra = ""
        if container:
            extra += f"--container {container} "
        self.pod = pod
        self.prefix_exec = f"kubectl exec {pod} -n {namespace} {extra}-- "

        self.prefix_logs = f"kubectl logs {pod} -n {namespace} {extra}"

    # TODO: api.connect_get_namespaced_pod_exec (to do exec using Python API programmatically)
    def execute(self, command):
        """Execute a command in pod.

        Args:
            command (str): Command to execute.

        Returns:
            tuple: 2-tuple of execution info:
            1) result of the command, if successful, None if not;
            2) and error, if command failed, None if not.

        """
        result, error = execute(self.prefix_exec + command)
        return result, error

    def logs(self, tail=-1, since_time=None):
        """Get logs from pod.

        Args:
            tail (int): How many lines of logs to obtain?

        Returns:
            str: Logs contained in pod.
        """
        command = f"--tail={tail}"
        if since_time:
            command += f" --since-time='{since_time}'"
        result, _ = execute(self.prefix_logs + command)
        return result
