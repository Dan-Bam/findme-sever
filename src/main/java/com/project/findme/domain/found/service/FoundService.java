package com.project.findme.domain.found.service;

import com.project.findme.domain.found.entity.Found;
import com.project.findme.domain.found.presentation.dto.CreateFoundRequest;
import com.project.findme.domain.found.presentation.dto.UpdateFoundRequest;
import com.project.findme.domain.image.entity.FoundImage;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface FoundService {

    void createFound(CreateFoundRequest createFoundRequest, List<MultipartFile> multipartFiles);
    FoundImage saveToUrl(Found found, String category, String uploadUrl);
    void updateFound(Long foundId, UpdateFoundRequest updateFoundRequest, List<MultipartFile> multipartFileList);
    void deleteFound(Long foundId);

}
