window.PhotoLibraryModal = (function () {
    let selectedAssets = new Map();
    let currentFolderId = null;
    let currentMode = 'multiple';
    let currentSectionId = null;
    let onConfirmCallback = null;
    let allowedType = 'image';

    const state = {
        folders: [],
        assets: []
    };

    function qs(id) {
        return document.getElementById(id);
    }

    function open(options = {}) {
        currentMode = options.mode || 'multiple';
        currentSectionId = options.sectionId || null;
        onConfirmCallback = typeof options.onConfirm === 'function' ? options.onConfirm : null;
        allowedType = options.assetType || 'image';
        currentFolderId = null;
        selectedAssets = new Map();

        const modal = qs('libraryModal');
        const title = modal?.querySelector('.library-header h2');
        const subtitle = qs('libraryModalSubtitle');
        const confirmButton = qs('libraryConfirmButton');

        if (title) {
            title.innerHTML = `<i class="fas fa-box-open"></i> ${options.title || 'Select from Asset Library'}`;
        }

        if (subtitle) {
            subtitle.textContent = options.subtitle || 'Choose images to add to your page section.';
        }

        if (confirmButton) {
            confirmButton.textContent = currentSectionId ? 'Add Selected to Section' : 'Use Selected Image';
        }

        if (modal) {
            modal.style.display = 'block';
        }

        loadRoot();
        updateSelectionCount();
    }

    function close() {
        const modal = qs('libraryModal');
        if (modal) modal.style.display = 'none';

        selectedAssets = new Map();
        currentFolderId = null;
        currentSectionId = null;
        onConfirmCallback = null;
    }

    async function loadRoot() {
        currentFolderId = null;

        const response = await fetch(`/admin/assets/root?type=${encodeURIComponent(allowedType)}`);
        const data = await response.json();

        state.folders = data.folders || [];
        state.assets = data.assets || [];

        renderFolders();
        renderAssets();

        const label = qs('modalCurrentFolderName');
        if (label) label.textContent = 'Root Images';
    }

    async function loadFolder(folderId, folderName = 'Folder') {
        currentFolderId = folderId;

        const response = await fetch(`/admin/assets/folder/${folderId}?type=${encodeURIComponent(allowedType)}`);
        const data = await response.json();

        state.assets = data.assets || [];

        renderAssets();

        const label = qs('modalCurrentFolderName');
        if (label) label.textContent = folderName;
    }

    function renderFolders() {
        const grid = qs('modalFolderGrid');
        if (!grid) return;

        grid.innerHTML = '';

        const root = document.createElement('div');
        root.className = `folder-item ${!currentFolderId ? 'active-folder' : ''}`;
        root.innerHTML = `
            <i class="fas fa-home fa-3x"></i>
            <p>Main Library</p>
        `;
        root.onclick = loadRoot;
        grid.appendChild(root);

        state.folders.forEach(folder => {
            const item = document.createElement('div');
            item.className = `folder-item ${String(currentFolderId) === String(folder.id) ? 'active-folder' : ''}`;
            item.innerHTML = `
                <i class="fas fa-folder fa-3x"></i>
                <p>${escapeHtml(folder.name)}</p>
            `;
            item.onclick = () => loadFolder(folder.id, folder.name);
            grid.appendChild(item);
        });
    }

    function renderAssets() {
        const grid = qs('modalImageGrid');
        if (!grid) return;

        grid.innerHTML = '';

        if (!state.assets.length) {
            grid.innerHTML = `
                <div class="library-empty-state">
                    No images here yet.
                </div>
            `;
            return;
        }

        state.assets.forEach(asset => {
            const card = document.createElement('div');
            card.className = 'image-card library-asset-card';
            card.dataset.assetId = asset.id;

            const imageUrl = asset.thumbnail_url || asset.thumbnailUrl || asset.url;

            card.innerHTML = `
                <div class="library-card-check">
                    <i class="fas fa-check"></i>
                </div>

                <img src="${imageUrl}" loading="lazy" alt="${escapeHtml(asset.original_filename || 'Asset image')}">

                <div class="library-asset-name" title="${escapeHtml(asset.original_filename || '')}">
                    ${escapeHtml(asset.original_filename || 'Image')}
                </div>
            `;

            if (selectedAssets.has(String(asset.id))) {
                card.classList.add('selected');
            }

            card.onclick = () => toggleAsset(asset, card);

            grid.appendChild(card);
        });
    }

    function toggleAsset(asset, card) {
        const key = String(asset.id);

        if (currentMode === 'single') {
            selectedAssets.clear();
            document.querySelectorAll('#modalImageGrid .image-card.selected').forEach(el => {
                el.classList.remove('selected');
            });
        }

        if (selectedAssets.has(key)) {
            selectedAssets.delete(key);
            card.classList.remove('selected');
        } else {
            selectedAssets.set(key, asset);
            card.classList.add('selected');
        }

        updateSelectionCount();
    }

    function updateSelectionCount() {
        const count = selectedAssets.size;
        const countEl = qs('selectionCount');

        if (!countEl) return;

        countEl.textContent = count === 1 ? '1 image selected' : `${count} images selected`;
    }

    async function confirmSelection() {
        const selected = Array.from(selectedAssets.values());

        if (!selected.length) {
            alert('Please select at least one image.');
            return;
        }

        const assetIds = selected.map(asset => asset.id);
        const assetUrls = selected.map(asset => asset.url);

        const payload = {
            mode: currentMode,
            assetIds,
            imageIds: assetIds,
            assetUrls,
            imageUrls: assetUrls,
            assets: selected,
            sectionId: currentSectionId
        };

        if (onConfirmCallback) {
            onConfirmCallback(payload);
            close();
            return;
        }

        if (!currentSectionId) {
            close();
            return;
        }

        const response = await fetch('/add_assets_to_section', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': typeof csrfToken !== 'undefined' ? csrfToken : ''
            },
            body: JSON.stringify({
                section_id: currentSectionId,
                asset_ids: assetIds,
                usage_type: 'section-image'
            })
        });

        const data = await response.json();

        if (data.success || data.status === 'success') {
    const sectionIdToRefresh = currentSectionId;

    if (typeof loadUploadedImages === 'function' && sectionIdToRefresh) {
        await loadUploadedImages(sectionIdToRefresh);

        setTimeout(() => {
            loadUploadedImages(sectionIdToRefresh);

            const sectionContent = document.getElementById(`section-content-${sectionIdToRefresh}`);

            if (
                sectionContent &&
                sectionContent.classList.contains('open') &&
                typeof updateOpenSectionLayout === 'function'
            ) {
                updateOpenSectionLayout(sectionContent);
            }
        }, 150);
    }

    if (typeof reloadIframe === 'function') {
        reloadIframe();
    }

    close();
} else {
    alert(data.error || data.message || 'Failed to add images.');
}
    }

    async function handleUpload(event) {
        const files = event.target.files;
        if (!files || !files.length) return;

        const formData = new FormData();

        Array.from(files).forEach(file => {
            formData.append('asset', file);
        });

        if (currentFolderId) {
            formData.append('folder_id', currentFolderId);
        }

        const progressWrapper = qs('modalUploadProgressWrapper');
        const progressFill = qs('modalUploadProgressFill');
        const progressText = qs('modalUploadProgressText');

        if (progressWrapper) progressWrapper.style.display = 'block';
        if (progressFill) progressFill.style.width = '0%';
        if (progressText) progressText.textContent = '0%';

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/admin/assets/upload', true);

        xhr.upload.addEventListener('progress', function (e) {
            if (!e.lengthComputable) return;

            const percent = Math.round((e.loaded / e.total) * 100);

            if (progressFill) progressFill.style.width = `${percent}%`;
            if (progressText) progressText.textContent = `${percent}%`;
        });

        xhr.onload = function () {
            event.target.value = '';

            if (xhr.status >= 200 && xhr.status < 300) {
                if (progressFill) progressFill.style.width = '100%';
                if (progressText) progressText.textContent = 'Upload complete';

                if (currentFolderId) {
                    loadFolder(currentFolderId, qs('modalCurrentFolderName')?.textContent || 'Folder');
                } else {
                    loadRoot();
                }

                setTimeout(() => {
                    if (progressWrapper) progressWrapper.style.display = 'none';
                }, 600);

                return;
            }

            let message = 'Upload failed.';

            try {
                const data = JSON.parse(xhr.responseText);
                message = data.error || data.message || message;
            } catch (_) { }

            alert(message);

            if (progressWrapper) progressWrapper.style.display = 'none';
        };

        xhr.onerror = function () {
            alert('Upload failed.');
            if (progressWrapper) progressWrapper.style.display = 'none';
        };

        xhr.send(formData);
    }

    async function createFolder() {
        const folderName = prompt('Folder name:');

        if (!folderName) return;

        const response = await fetch('/admin/assets/create_folder', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': typeof csrfToken !== 'undefined' ? csrfToken : ''
            },
            body: JSON.stringify({
                name: folderName,
                asset_type: allowedType
            })
        });

        const data = await response.json();

        if (data.success || data.status === 'success') {
            loadRoot();
        } else {
            alert(data.message || data.error || 'Failed to create folder.');
        }
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#039;');
    }

    return {
        open,
        close,
        confirmSelection,
        handleUpload,
        createFolder,
        loadRoot,
        loadFolder
    };
})();