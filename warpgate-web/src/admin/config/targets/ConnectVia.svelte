<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type ConnectVia, type Target } from 'admin/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import { TargetKind } from 'gateway/lib/api'

    interface Props {
        connectVia: ConnectVia | undefined
    }

    let { connectVia = $bindable() }: Props = $props()

    async function loadTunnelTargets(): Promise<{
        kubernetes: Target[]
        ssh: Target[]
    }> {
        const targets = await api.getTargets()
        return {
            kubernetes: targets.filter(t => t.options.kind === TargetKind.Kubernetes),
            ssh: targets.filter(t => t.options.kind === TargetKind.Ssh),
        }
    }

    function enableKubernetes(kubernetesTargets: Target[]) {
        connectVia = {
            kind: 'Kubernetes',
            kubernetesTargetId: kubernetesTargets[0]?.id ?? '',
            namespace: 'default',
            service: '',
            port: 0,
        }
    }

    function enableSsh(sshTargets: Target[]) {
        connectVia = {
            kind: 'Ssh',
            sshTargetId: sshTargets[0]?.id ?? '',
            host: '127.0.0.1',
            port: 0,
        }
    }
</script>

<h5 class="mt-3">Tunnel</h5>
<p class="text-muted small">
    Reach a backend Warpgate has no direct network path to by tunneling
    through another target's own connection instead of connecting to the
    host/port above directly - a Kubernetes target's port-forward API, or an
    SSH target's <code>direct-tcpip</code> channel (the same primitive
    <code>ssh -L</code> uses, including through that target's own jump-host
    chain, if it has one).
</p>

<Loadable promise={loadTunnelTargets()}>
    {#snippet children(tunnelTargets)}
        {@const hasAnyTargets = tunnelTargets.kubernetes.length > 0 || tunnelTargets.ssh.length > 0}

        <label for="connectViaEnabled" class="d-flex align-items-center mb-2">
            <Input
                id="connectViaEnabled"
                class="mb-0 me-2"
                type="switch"
                checked={!!connectVia}
                disabled={!hasAnyTargets}
                on:change={e => {
                    if (!e.currentTarget.checked) {
                        connectVia = undefined
                    } else if (tunnelTargets.kubernetes.length > 0) {
                        enableKubernetes(tunnelTargets.kubernetes)
                    } else {
                        enableSsh(tunnelTargets.ssh)
                    }
                }}
            />
            <div>Route through a tunnel</div>
        </label>

        {#if !hasAnyTargets}
            <p class="text-muted small">
                No <code>Kubernetes</code> or <code>Ssh</code>-kind targets are
                configured yet - add one first to enable this.
            </p>
        {/if}

        {#if connectVia}
            <FormGroup floating label="Tunnel through">
                <select
                    class="form-control"
                    value={connectVia.kind}
                    onchange={e => {
                        const kind = e.currentTarget.value
                        if (kind === 'Kubernetes') {
                            enableKubernetes(tunnelTargets.kubernetes)
                        } else {
                            enableSsh(tunnelTargets.ssh)
                        }
                    }}
                >
                    {#if tunnelTargets.kubernetes.length > 0}
                        <option value="Kubernetes">A Kubernetes target</option>
                    {/if}
                    {#if tunnelTargets.ssh.length > 0}
                        <option value="Ssh">An SSH target</option>
                    {/if}
                </select>
            </FormGroup>

            {#if connectVia.kind === 'Kubernetes'}
                <FormGroup floating label="Kubernetes target">
                    <select
                        class="form-control"
                        bind:value={connectVia.kubernetesTargetId}
                    >
                        {#each tunnelTargets.kubernetes as kubernetesTarget (kubernetesTarget.id)}
                            <option value={kubernetesTarget.id}>
                                {kubernetesTarget.name}
                            </option>
                        {/each}
                    </select>
                </FormGroup>

                <div class="row">
                    <div class="col">
                        <FormGroup floating label="Namespace">
                            <input
                                class="form-control"
                                bind:value={connectVia.namespace}
                            >
                        </FormGroup>
                    </div>
                    <div class="col">
                        <FormGroup floating label="Service name">
                            <input
                                class="form-control"
                                bind:value={connectVia.service}
                            >
                        </FormGroup>
                    </div>
                    <div class="col-3">
                        <FormGroup floating label="Service port">
                            <input
                                class="form-control"
                                type="number"
                                bind:value={connectVia.port}
                                min="1"
                                max="65535"
                                step="1"
                            >
                        </FormGroup>
                    </div>
                </div>
            {:else}
                <FormGroup floating label="SSH target">
                    <select class="form-control" bind:value={connectVia.sshTargetId}>
                        {#each tunnelTargets.ssh as sshTarget (sshTarget.id)}
                            <option value={sshTarget.id}>{sshTarget.name}</option>
                        {/each}
                    </select>
                </FormGroup>
                <p class="text-muted small">
                    Also follows that target's own jump-host chain, if it has
                    one.
                </p>

                <div class="row">
                    <div class="col-8">
                        <FormGroup floating label="Host (as reached from the SSH target)">
                            <input
                                class="form-control"
                                bind:value={connectVia.host}
                                placeholder="127.0.0.1"
                            >
                        </FormGroup>
                    </div>
                    <div class="col-4">
                        <FormGroup floating label="Port">
                            <input
                                class="form-control"
                                type="number"
                                bind:value={connectVia.port}
                                min="1"
                                max="65535"
                                step="1"
                            >
                        </FormGroup>
                    </div>
                </div>
            {/if}
        {/if}
    {/snippet}
</Loadable>
