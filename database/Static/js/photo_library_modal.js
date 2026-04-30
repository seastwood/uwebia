window.PhotoLibraryModal = (function () {
    let mode = 'section-images';
    let currentTargetSection = null;
    let selectedImageIds = [];
    let selectedImageUrls = [];
    let currentActiveFolderId = null;
    let globalFoldersCache = [];

    let onConfirmCallback = null;

    async function open(options = {}) {
        mode = options.mode || 'section-images';
        currentTargetSection = options.sectionId || null;
        onConfirmCallback = options.onConfirm || null;

        selectedImageIds = [];
        selectedImageUrls = [];

        setModeText();

        const modal = document.getElementById('libraryModal');
        if (modal) {
            modal.style.display = 'block';
        }

        const response = await fetch('/get_library_root');
        const data = await response.json();

        globalFoldersCache = data.folders || [];

        await loadUI(null);
    }

    function close() {
        const modal = document.getElementById('libraryModal');

        if (modal) {
            modal.style.display = 'none';
        }
    }

    function setModeText() {
        const subtitle = document.getElementById('libraryModalSubtitle');
        const button = document.getElementById('libraryConfirmButton');
        const count = document.getElementById('selectionCount');

        const singleImageModes = [
            'group-background',
            'website-background',
            'single-image'
        ];

        if (singleImageModes.includes(mode)) {
            if (subtitle) subtitle.textContent = 'Choose one image from your photo library.';
            if (button) button.textContent = 'Use Selected Image';
            if (count) count.textContent = '0 images selected';
            return;
        }

        if (subtitle) subtitle.textContent = 'Choose images to add to your page section.';
        if (button) button.textContent = 'Add Selected to Section';
        if (count) count.textContent = '0 images selected';
    }

    async function loadUI(folderId = null) {
        currentActiveFolderId = folderId || null;

        renderFolders(globalFoldersCache, folderId);

        const url = folderId ? `/get_library_folder/${folderId}` : '/get_library_root';
        const response = await fetch(url);
        const data = await response.json();

        const folderName = document.getElementById('modalCurrentFolderName');
        if (folderName) {
            folderName.innerText = folderId
                ? `Images in ${data.current_folder_name || 'Folder'}`
                : 'Root Images';
        }

        const imageGrid = document.getElementById('modalImageGrid');
        if (!imageGrid) return;

        imageGrid.innerHTML = '';

        if (!data.images || data.images.length === 0) {
            imageGrid.innerHTML = `
                <p style="grid-column: 1/-1; text-align: center; color: rgba(255,255,255,0.55);">
                    No images found in this folder.
                </p>
            `;
            return;
        }

        data.images.forEach(img => {
            const imageId = String(img.id);
            const imageUrl = img.url;
            const thumbUrl = img.thumbnail_url || img.url;

            const card = document.createElement('div');
            card.className = 'image-card';
            card.dataset.imageId = imageId;
            card.dataset.imageUrl = imageUrl;

            if (selectedImageIds.includes(imageId)) {
                card.classList.add('selected');
            }

            card.onclick = () => toggleSelection(imageId, imageUrl, card);

            card.innerHTML = `
                <img src="${thumbUrl}" loading="lazy">
                <button type="button"
                    class="modal-library-delete-btn"
                    onclick="PhotoLibraryModal.deleteImage(event, '${imageId}')">
                    <i class="fas fa-trash"></i>
                </button>
            `;

            imageGrid.appendChild(card);
        });
    }

    function renderFolders(folders, activeId) {
        const grid = document.getElementById('modalFolderGrid');
        if (!grid) return;

        grid.innerHTML = '';

        const rootDiv = document.createElement('div');
        rootDiv.className = `folder-item ${activeId === null ? 'active-folder' : ''}`;
        rootDiv.onclick = () => loadUI(null);
        rootDiv.innerHTML = `<i class="fas fa-home fa-3x"></i><p>Main Library</p>`;
        grid.appendChild(rootDiv);

        folders.forEach(folder => {
            const folderDiv = document.createElement('div');
            folderDiv.className = `folder-item ${activeId == folder.id ? 'active-folder' : ''}`;
            folderDiv.onclick = () => loadUI(folder.id);
            folderDiv.innerHTML = `<i class="fas fa-folder fa-3x"></i><p>${folder.name}</p>`;
            grid.appendChild(folderDiv);
        });
    }

    function isSingleImageMode() {
        return ['group-background', 'website-background', 'single-image'].includes(mode);
    }

    function toggleSelection(id, imageUrl, element) {
        if (isSingleImageMode()) {
            selectedImageIds = [id];
            selectedImageUrls = [imageUrl];

            document.querySelectorAll('#modalImageGrid .image-card').forEach(card => {
                card.classList.remove('selected');
            });

            element.classList.add('selected');

            updateSelectionCount();
            return;
        }

        const index = selectedImageIds.indexOf(id);

        if (index > -1) {
            selectedImageIds.splice(index, 1);
            selectedImageUrls.splice(index, 1);
            element.classList.remove('selected');
        } else {
            selectedImageIds.push(id);
            selectedImageUrls.push(imageUrl);
            element.classList.add('selected');
        }

        updateSelectionCount();
    }

    function updateSelectionCount() {
        const count = document.getElementById('selectionCount');
        if (!count) return;

        const amount = selectedImageIds.length;
        count.textContent = `${amount} image${amount === 1 ? '' : 's'} selected`;
    }

    async function confirmSelection() {
        if (selectedImageIds.length === 0) return;

        if (typeof onConfirmCallback === 'function') {
            onConfirmCallback({
                mode,
                imageIds: selectedImageIds,
                imageUrls: selectedImageUrls,
                sectionId: currentTargetSection
            });

            close();
            return;
        }

        if (mode === 'section-images') {
            await addSelectedImagesToSection();
            return;
        }

        close();
    }

    async function addSelectedImagesToSection() {
        if (!currentTargetSection) return;

        const response = await fetch('/add_images_from_library', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                section_id: currentTargetSection,
                image_ids: selectedImageIds
            })
        });

        if (response.ok) {
            close();

            if (typeof loadUploadedImages === 'function') {
                loadUploadedImages(currentTargetSection);
            }
        }
    }

    async function handleUpload(event) {
        const files = event.target.files;

        if (!files || files.length === 0) return;

        const maxFileSizeMb = 10;
        const maxFileSizeBytes = maxFileSizeMb * 1024 * 1024;

        for (const file of files) {
            if (file.size > maxFileSizeBytes) {
                alert(`"${file.name}" is too large. Max allowed size is ${maxFileSizeMb} MB per image.`);
                event.target.value = '';
                return;
            }
        }

        const formData = new FormData();

        Array.from(files).forEach(file => {
            formData.append('picture', file);
        });

        if (currentActiveFolderId) {
            formData.append('folder_id', currentActiveFolderId);
        }

        const progressWrapper = document.getElementById('modalUploadProgressWrapper');
        const progressFill = document.getElementById('modalUploadProgressFill');
        const progressText = document.getElementById('modalUploadProgressText');

        if (progressWrapper) progressWrapper.style.display = 'block';
        if (progressFill) progressFill.style.width = '0%';
        if (progressText) progressText.textContent = '0%';

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/admin/library/upload', true);

        xhr.upload.addEventListener('progress', function (e) {
            if (!e.lengthComputable) return;

            const percent = Math.round((e.loaded / e.total) * 100);

            if (progressFill) progressFill.style.width = `${percent}%`;
            if (progressText) progressText.textContent = `${percent}%`;
        });

        xhr.onload = async function () {
            if (xhr.status >= 200 && xhr.status < 300) {
                if (progressFill) progressFill.style.width = '100%';
                if (progressText) progressText.textContent = 'Upload complete';

                event.target.value = '';

                await refreshFoldersCache();
                await loadUI(currentActiveFolderId);

                setTimeout(() => {
                    if (progressWrapper) progressWrapper.style.display = 'none';
                    if (progressFill) progressFill.style.width = '0%';
                    if (progressText) progressText.textContent = '0%';
                }, 800);

                return;
            }

            alert('Upload failed.');

            if (progressWrapper) {
                progressWrapper.style.display = 'none';
            }
        };

        xhr.onerror = function () {
            alert('Upload failed.');

            if (progressWrapper) {
                progressWrapper.style.display = 'none';
            }
        };

        xhr.send(formData);
    }

    async function refreshFoldersCache() {
        const response = await fetch('/get_library_root');
        const data = await response.json();

        globalFoldersCache = data.folders || [];
    }

    async function createFolder() {
        const folderName = prompt('Folder name:');

        if (!folderName) return;

        const response = await fetch('/admin/library/create_folder', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: folderName
            })
        });

        if (!response.ok) {
            alert('Failed to create folder.');
            return;
        }

        await refreshFoldersCache();
        await loadUI(currentActiveFolderId);
    }

    async function deleteImage(event, imageId) {
        event.preventDefault();
        event.stopPropagation();

        if (!confirm('Delete this image from the library?')) return;

        const response = await fetch(`/admin/library/delete_image/${imageId}`, {
            method: 'POST'
        });

        if (!response.ok) {
            alert('Failed to delete image.');
            return;
        }

        selectedImageIds = selectedImageIds.filter(id => id !== String(imageId));
        selectedImageUrls = selectedImageUrls.filter((_, index) => selectedImageIds[index] !== String(imageId));

        await loadUI(currentActiveFolderId);
    }

    return {
        open,
        close,
        confirmSelection,
        handleUpload,
        createFolder,
        deleteImage,
        loadUI
    };
})();