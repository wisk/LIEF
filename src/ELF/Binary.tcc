/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "LIEF/logging++.hpp"
#include "LIEF/ELF/enums.hpp"
namespace LIEF {
  namespace ELF {

    // ===============
    // ARM Relocations
    // ===============
    template<>
    void Binary::patch_relocations<ARCH::EM_ARM>(uint64_t from, uint64_t shift) {
      for (Relocation& relocation : this->relocations()) {

        if (relocation.address() >= from) {
          //this->shift_code(relocation.address(), shift, relocation.size() / 8);
          relocation.address(relocation.address() + shift);
        }

        const RELOC_ARM type = static_cast<RELOC_ARM>(relocation.type());

        switch (type) {
        case RELOC_ARM::R_ARM_JUMP_SLOT:
        case RELOC_ARM::R_ARM_RELATIVE:
        case RELOC_ARM::R_ARM_GLOB_DAT:
        case RELOC_ARM::R_ARM_IRELATIVE:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

        default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
        }
      }
    }


    // ===================
    // AARCH64 Relocations
    // ===================
    template<>
    void Binary::patch_relocations<ARCH::EM_AARCH64>(uint64_t from, uint64_t shift) {
      for (Relocation& relocation : this->relocations()) {

        if (relocation.address() >= from) {
          //this->shift_code(relocation.address(), shift, relocation.size() / 8);
          relocation.address(relocation.address() + shift);
        }

        const RELOC_AARCH64 type = static_cast<RELOC_AARCH64>(relocation.type());

        switch (type) {
        case RELOC_AARCH64::R_AARCH64_JUMP_SLOT:
        case RELOC_AARCH64::R_AARCH64_RELATIVE:
        case RELOC_AARCH64::R_AARCH64_GLOB_DAT:
        case RELOC_AARCH64::R_AARCH64_IRELATIVE:
        case RELOC_AARCH64::R_AARCH64_ABS64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

        case RELOC_AARCH64::R_AARCH64_ABS32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

        case RELOC_AARCH64::R_AARCH64_ABS16:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint16_t>(relocation, from, shift);
          break;
        }


        case RELOC_AARCH64::R_AARCH64_PREL64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

        case RELOC_AARCH64::R_AARCH64_PREL32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

        case RELOC_AARCH64::R_AARCH64_PREL16:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint16_t>(relocation, from, shift);
          break;
        }

        default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
        }
      }
    }

    // ==================
    // x86_32 Relocations
    // ==================
    template<>
    void Binary::patch_relocations<ARCH::EM_386>(uint64_t from, uint64_t shift) {
      for (Relocation& relocation : this->relocations()) {
        if (relocation.address() >= from) {
          //this->shift_code(relocation.address(), shift, relocation.size() / 8);
          relocation.address(relocation.address() + shift);
        }

        const RELOC_i386 type = static_cast<RELOC_i386>(relocation.type());

        switch (type) {
        case RELOC_i386::R_386_RELATIVE:
        case RELOC_i386::R_386_JUMP_SLOT:
        case RELOC_i386::R_386_IRELATIVE:
        case RELOC_i386::R_386_GLOB_DAT:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

        default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
        }
      }
    }

    // ==================
    // x86_64 Relocations
    // ==================
    template<>
    void Binary::patch_relocations<ARCH::EM_X86_64>(uint64_t from, uint64_t shift) {
      for (Relocation& relocation : this->relocations()) {
        if (relocation.address() >= from) {
          //this->shift_code(relocation.address(), shift, relocation.size() / 8);
          relocation.address(relocation.address() + shift);
        }

        const RELOC_x86_64 type = static_cast<RELOC_x86_64>(relocation.type());
        switch (type) {
        case RELOC_x86_64::R_X86_64_RELATIVE:
        case RELOC_x86_64::R_X86_64_IRELATIVE:
        case RELOC_x86_64::R_X86_64_JUMP_SLOT:
        case RELOC_x86_64::R_X86_64_GLOB_DAT:
        case RELOC_x86_64::R_X86_64_64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

        case RELOC_x86_64::R_X86_64_32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

        default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
        }
      }
    }


    // ==================
    // PPC_32 Relocations
    // ==================
    template<>
    void Binary::patch_relocations<ARCH::EM_PPC>(uint64_t from, uint64_t shift) {
      for (Relocation& relocation : this->relocations()) {
        if (relocation.address() >= from) {
          relocation.address(relocation.address() + shift);
        }

        const RELOC_POWERPC32 type = static_cast<RELOC_POWERPC32>(relocation.type());

        switch (type) {
        case RELOC_POWERPC32::R_PPC_RELATIVE:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

        default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
        }
      }
    }


    template<class T>
    void Binary::patch_addend(Relocation & relocation, uint64_t from, uint64_t shift) {

      if (static_cast<uint64_t>(relocation.addend()) >= from) {
        relocation.addend(relocation.addend() + shift);
      }

      const uint64_t address = relocation.address();
      VLOG(VDEBUG) << "Patch addend relocation at address: 0x" << std::hex << address;
      Segment& segment = segment_from_virtual_address(address);
      const uint64_t relative_offset = this->virtual_address_to_offset(address) - segment.file_offset();
      std::vector<uint8_t> segment_content = segment.content();
      const size_t segment_size = segment_content.size();

      if (segment_size == 0) {
        LOG(WARNING) << "Segment is empty nothing to do";
        return;
      }

      if (relative_offset >= segment_size or (relative_offset + sizeof(T)) >= segment_size) {
        VLOG(VDEBUG) << "Offset out of bound for relocation: " << relocation;
        return;
      }

      T* value = reinterpret_cast<T*>(segment_content.data() + relative_offset);

      if (value != nullptr and *value >= from) {
        *value += shift;
      }

      segment.content(segment_content);
    }


    // ========
    // ET_EXEC
    // ========
    template<>
    Segment& Binary::add_segment<E_TYPE::ET_EXEC>(const Segment& segment, uint64_t base) {

      //Header& header = this->header();

      //// TODO: Remove this since it'll be calculated during the building process

      //// ------------------------------------------
      //// Part 1: Move PHDR at the end of the binary
      //// ------------------------------------------
      //header.numberof_segments(header.numberof_segments() + 1);

      //auto && it_text_segment = std::find_if(
      //  std::begin(this->segments_),
      //  std::end(this->segments_),
      //  [](const Segment * s) {
      //    return s->type() == SEGMENT_TYPES::PT_LOAD and
      //      s->has(ELF_SEGMENT_FLAGS::PF_X) and s->has(ELF_SEGMENT_FLAGS::PF_R);
      //  });

      //Segment * text_segment = nullptr;
      //if (it_text_segment != std::end(this->segments_)) {
      //  //throw not_found("Unable to find a LOAD segment with 'r-x' permissions");
      //  text_segment = *it_text_segment;
      //}


      //uint64_t last_offset_sections = std::accumulate(
      //  std::begin(this->sections_),
      //  std::end(this->sections_), 0,
      //  [](uint64_t offset, const Section * section) {
      //    return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      //  });

      //uint64_t last_offset_segments = std::accumulate(
      //  std::begin(this->segments_),
      //  std::end(this->segments_), 0,
      //  [](uint64_t offset, const Segment * segment) {
      //    return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      //  });

      //uint64_t last_offset = std::max<uint64_t>(last_offset_sections, last_offset_segments);
      //uint64_t new_phdr_offset = last_offset;

      //VLOG(VDEBUG) << "New PHDR offset 0x" << std::hex << new_phdr_offset;
      //header.program_headers_offset(new_phdr_offset);

      //uint64_t phdr_size = 0;
      //if (this->type() == ELF_CLASS::ELFCLASS32) {
      //  phdr_size = sizeof(ELF32::Elf_Phdr);
      //}

      //if (this->type() == ELF_CLASS::ELFCLASS64) {
      //  phdr_size = sizeof(ELF64::Elf_Phdr);
      //}

      //auto&& it_segment_phdr = std::find_if(
      //  std::begin(this->segments_),
      //  std::end(this->segments_),
      //  [](const Segment * s)
      //  {
      //    return s != nullptr and s->type() == SEGMENT_TYPES::PT_PHDR;
      //  });

      //if (it_segment_phdr != std::end(this->segments_)) {
      //  Segment* phdr_segment = *it_segment_phdr;

      //  const uint64_t new_phdr_size = phdr_segment->physical_size() + phdr_size;

      //  VLOG(VDEBUG) << "New PHDR size 0x" << std::hex << new_phdr_size;

        //phdr_segment->file_offset(new_phdr_offset);
        //phdr_segment->virtual_address(text_segment->virtual_address() - text_segment->file_offset() + phdr_segment->file_offset());

        //phdr_segment->physical_address(phdr_segment->virtual_address());

        //phdr_segment->physical_size(new_phdr_size);
        //phdr_segment->virtual_size(phdr_segment->virtual_size() + phdr_size);

        //uint64_t gap  = phdr_segment->file_offset() + phdr_segment->physical_size();
        //         gap -= text_segment->file_offset() + text_segment->physical_size();

        //text_segment->physical_size(text_segment->physical_size() + gap);
        //text_segment->virtual_size(text_segment->virtual_size() + gap);

        // Clear PHDR segment
      //  phdr_segment->content(std::vector<uint8_t>(phdr_segment->physical_size(), 0));
      //}

      //if (header.section_headers_offset() <= new_phdr_offset + phdr_size * header.numberof_segments()) {
      //  header.section_headers_offset(header.section_headers_offset() + new_phdr_offset + phdr_size * header.numberof_segments());
      //}

      // Extend the segment so that it wraps the PHDR segment
      //this->datahandler_->make_hole(new_phdr_offset, phdr_size * header.numberof_segments());

      // --------------------------------------
      // Part 2: Add the segment
      // --------------------------------------
      std::vector<uint8_t> content = segment.content();
      Segment* new_segment = new Segment{ segment };

      if (segment.file_fixed()) {
        new_segment->datahandler_ = this->datahandler_;

        DataHandler::Node new_node{
                new_segment->file_offset(),
                new_segment->physical_size(),
                DataHandler::Node::SEGMENT };
        this->datahandler_->add(new_node);
      }


      //last_offset_sections = std::accumulate(
      //  std::begin(this->sections_),
      //  std::end(this->sections_), 0,
      //  [](uint64_t offset, const Section * section) {
      //    return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      //  });

      //last_offset_segments = std::accumulate(
      //  std::begin(this->segments_),
      //  std::end(this->segments_), 0,
      //  [](uint64_t offset, const Segment * segment) {
      //    return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      //  });

      //last_offset = std::max<uint64_t>(last_offset_sections, last_offset_segments);

      const uint64_t psize = static_cast<uint64_t>(getpagesize());
      //const uint64_t last_offset_aligned = align(last_offset, psize);
      //new_segment->file_offset(last_offset_aligned);

      //if (segment.virtual_address() == 0) {
      //  new_segment->virtual_address(base + last_offset_aligned);
      //}

      //new_segment->physical_address(new_segment->virtual_address());

      uint64_t segmentsize = align(content.size(), psize);
      content.resize(segmentsize, 0);

      new_segment->physical_size(segmentsize);
      new_segment->virtual_size(segmentsize);

      if (new_segment->alignment() == 0) {
        new_segment->alignment(psize);
      }

      //this->datahandler_->make_hole(last_offset_aligned, new_segment->physical_size());
      new_segment->content(content);


      //if (it_segment_phdr == std::end(this->segments_)) { // Static binary
      //  if (header.program_headers_offset() <= new_segment->file_offset() + new_segment->physical_size()) {
      //    header.program_headers_offset(header.program_headers_offset() + new_segment->file_offset() + new_segment->physical_size());
      //  }
      //}
      //if (header.section_headers_offset() <= new_segment->file_offset() + new_segment->physical_size()) {
      //  header.section_headers_offset(header.section_headers_offset() + new_segment->file_offset() + new_segment->physical_size());
      //}



      auto&& it_new_segment_place = std::find_if(
        this->segments_.rbegin(),
        this->segments_.rend(),
        [&new_segment](const Segment * s) {
          return s->type() == new_segment->type();
        });
      if (it_new_segment_place == this->segments_.rend()) {
        this->segments_.push_back(new_segment);
      }
      else {
        const size_t idx = std::distance(std::begin(this->segments_), it_new_segment_place.base());
        this->segments_.insert(std::begin(this->segments_) + idx, new_segment);
      }

      return *new_segment;
    }


    // =======================
    // ET_DYN (PIE/Libraries)
    // =======================
    template<>
    Segment& Binary::add_segment<E_TYPE::ET_DYN>(const Segment & segment, uint64_t base) {

      const uint64_t psize = static_cast<uint64_t>(getpagesize());

      // --------------------------------------
      // Part 1: Make spaces for a new PHDR
      // --------------------------------------
      const uint64_t phdr_offset = this->header().program_headers_offset();
      uint64_t phdr_size = 0;

      if (this->type() == ELF_CLASS::ELFCLASS32) {
        phdr_size = sizeof(ELF32::Elf_Phdr);
      }

      if (this->type() == ELF_CLASS::ELFCLASS64) {
        phdr_size = sizeof(ELF64::Elf_Phdr);
      }

      this->datahandler_->make_hole(phdr_offset + phdr_size * this->segments_.size(), psize);

      uint64_t from = phdr_offset + phdr_size * this->segments_.size();
      // TODO: Improve (It takes too much spaces)
      uint64_t shift = psize;

      VLOG(VDEBUG) << "Header shift: " << std::hex << shift;

      this->header().section_headers_offset(this->header().section_headers_offset() + shift);

      this->shift_sections(from, shift);
      this->shift_segments(from, shift);

      // Patch segment size for the segment which contains the new segment
      for (Segment* segment : this->segments_) {
        if ((segment->file_offset() + segment->physical_size()) >= from and
          from >= segment->file_offset()) {
          segment->virtual_size(segment->virtual_size() + shift);
          segment->physical_size(segment->physical_size() + shift);
        }
      }

      this->shift_dynamic_entries(from, shift);
      this->shift_symbols(from, shift);
      this->shift_relocations(from, shift);

      if (this->header().entrypoint() >= from) {
        this->header().entrypoint(this->header().entrypoint() + shift);
      }

      // --------------------------------------
      // Part 2: Add the segment
      // --------------------------------------
      std::vector<uint8_t> content = segment.content();
      Segment* new_segment = new Segment{ segment };

      if (segment.file_fixed()) {
        new_segment->datahandler_ = this->datahandler_;

        DataHandler::Node new_node{
                new_segment->file_offset(),
                new_segment->physical_size(),
                DataHandler::Node::SEGMENT };
        this->datahandler_->add(new_node);
      }

      //const uint64_t last_offset_sections = this->last_offset_section();
      //const uint64_t last_offset_segments = this->last_offset_segment();
      //const uint64_t last_offset = std::max<uint64_t>(last_offset_sections, last_offset_segments);
      //const uint64_t last_offset_aligned = align(last_offset, psize);

      //new_segment->file_offset(last_offset_aligned);
      //new_segment->virtual_address(new_segment->file_offset() + base);
      //new_segment->physical_address(new_segment->virtual_address());

      uint64_t segmentsize = align(content.size(), psize);
      content.resize(segmentsize);

      new_segment->physical_size(segmentsize);
      new_segment->virtual_size(segmentsize);

      if (new_segment->alignment() == 0) {
        new_segment->alignment(psize);
      }

      // Patch SHDR
      Header& header = this->header();
      const uint64_t new_section_hdr_offset = new_segment->file_offset() + new_segment->physical_size();
      header.section_headers_offset(new_section_hdr_offset);

      //this->datahandler_->make_hole(last_offset_aligned, new_segment->physical_size());

      new_segment->content(content);

      header.numberof_segments(header.numberof_segments() + 1);

      auto && it_new_segment_place = std::find_if(
        this->segments_.rbegin(),
        this->segments_.rend(),
        [&new_segment](const Segment * s) {
          return s->type() == new_segment->type();
        });
      if (it_new_segment_place == this->segments_.rend()) {
        this->segments_.push_back(new_segment);
      }
      else {
        const size_t idx = std::distance(std::begin(this->segments_), it_new_segment_place.base());
        this->segments_.insert(std::begin(this->segments_) + idx, new_segment);
      }

      return *new_segment;
    }


    // =======================
    // Extend PT_LOAD
    // =======================
    template<>
    Segment& Binary::extend_segment<SEGMENT_TYPES::PT_LOAD>(const Segment & segment, uint64_t size) {

      auto&& it_segment = std::find_if(
        std::begin(this->segments_),
        std::end(this->segments_),
        [&segment](const Segment * s) {
          return *s == segment;
        });

      if (it_segment == std::end(this->segments_)) {
        throw not_found("Unable to find the segment in the current binary");
      }

      Segment* segment_to_extend = *it_segment;


      uint64_t from_offset = segment_to_extend->file_offset() + segment_to_extend->physical_size();
      uint64_t from_address = segment_to_extend->virtual_address() + segment_to_extend->virtual_size();
      uint64_t shift = size;

      this->datahandler_->make_hole(
        segment_to_extend->file_offset() + segment_to_extend->physical_size(),
        size);

      this->shift_sections(from_offset, shift);
      this->shift_segments(from_offset, shift);

      // Shift
      segment_to_extend->physical_size(segment_to_extend->physical_size() + size);
      segment_to_extend->virtual_size(segment_to_extend->virtual_size() + size);

      std::vector<uint8_t> segment_content = segment_to_extend->content();
      segment_content.resize(segment_to_extend->physical_size(), 0);
      segment_to_extend->content(segment_content);

      // Patches
      this->header().section_headers_offset(this->header().section_headers_offset() + shift);

      this->shift_dynamic_entries(from_address, shift);
      this->shift_symbols(from_address, shift);
      this->shift_relocations(from_address, shift);

      if (this->header().entrypoint() >= from_address) {
        this->header().entrypoint(this->header().entrypoint() + shift);
      }

      return *segment_to_extend;
    }


    template<>
    Section& Binary::add_section<false>(const Section& section) {

      // TODO: Code dup
      if (this->sections_.size() == 0 and section.type() != ELF_SECTION_TYPES::SHT_NULL) {
        Section* null_section = new Section{ "", ELF_SECTION_TYPES::SHT_NULL };
        null_section->alignment(0);
        null_section->file_fixed(true);
        null_section->memory_fixed(true);
        this->sections_.push_back(null_section);
        this->header().numberof_sections(this->header().numberof_sections() + 1);
      }

      Section* new_section = new Section{ section };

      if (section.file_fixed()) {
        new_section->datahandler_ = this->datahandler_;

        DataHandler::Node new_node{
                new_section->file_offset(),
                new_section->size(),
                DataHandler::Node::SECTION };
        this->datahandler_->add(new_node);
        //const uint64_t last_offset_sections = this->last_offset_section();
        //const uint64_t last_offset_segments = this->last_offset_segment();
        //const uint64_t last_offset = std::max<uint64_t>(last_offset_sections, last_offset_segments);
        //new_section->offset(last_offset);
        this->datahandler_->make_hole(section.file_offset(), section.size());
      }

      new_section->size(section.size());

      // Copy original content in the data handler
      new_section->content(section.content());

      this->header().numberof_sections(this->header().numberof_sections() + 1);

      this->sections_.push_back(new_section);
      return *(this->sections_.back());
    }


    template<>
    Section& Binary::add_section<true>(const Section & section) {

      VLOG(VDEBUG) << "Adding section '" << section << "' in the binary (LOADED)";

      // Usually, null section must not be loadable
      if (this->sections_.size() == 0 and section.type() != ELF_SECTION_TYPES::SHT_NULL) {
        Section* null_section = new Section{ "", ELF_SECTION_TYPES::SHT_NULL };
        null_section->alignment(0);
        null_section->file_fixed(true);
        null_section->memory_fixed(true);
        this->sections_.push_back(null_section);
        this->header().numberof_sections(this->header().numberof_sections() + 1);
      }

      // Determine the segment type from the section type
      SEGMENT_TYPES segment_type;
      bool section_is_bss = false;
      switch (section.type()) {
      case ELF_SECTION_TYPES::SHT_DYNAMIC:
        {
          segment_type = SEGMENT_TYPES::PT_DYNAMIC;
          break;
        }

      case ELF_SECTION_TYPES::SHT_NOTE:
        {
          segment_type = SEGMENT_TYPES::PT_NOTE;
          break;
        }

      case ELF_SECTION_TYPES::SHT_NOBITS:
        {
          segment_type = SEGMENT_TYPES::PT_LOAD;
          section_is_bss = true;
          break;
        }

      default:
        {
          segment_type = SEGMENT_TYPES::PT_LOAD;
          break;
        }
      }

      // Determine the segment flags
      ELF_SEGMENT_FLAGS segment_flags = ELF_SEGMENT_FLAGS::PF_R;
      if (section.has(ELF_SECTION_FLAGS::SHF_WRITE)) {
        segment_flags |= ELF_SEGMENT_FLAGS::PF_W;
      }

      if (section.has(ELF_SECTION_FLAGS::SHF_EXECINSTR)) {
        segment_flags |= ELF_SEGMENT_FLAGS::PF_X;
      }

      // We try to reuse an unfixed segment
      if (this->segments_.size() > 0) {
        for (Segment* segment : this->segments_) {

          // Ignore fixed segments
          if (segment->file_fixed() or segment->memory_fixed())
            continue;

          // If the type doesn't match, leave
          if (segment->type() != segment_type)
            continue;

          // Do the same for flags
          if (segment->flags() != segment_flags)
            continue;

          std::vector<uint8_t> section_content = section.content();
          uint64_t section_file_size = section_content.size();

          // BSS
          if (not(
            (section_file_size == 0 and segment->physical_size() == 0) or
            (section_file_size != 0 and segment->physical_size() != 0)))
            continue;

          VLOG(VDEBUG) << "Segment reused: '" << *segment << "'";

          // Update alignment if needed
          if (section.alignment() > segment->alignment()) {
            segment->alignment(section.alignment());
          }

          uint64_t segment_end = segment->file_offset() + segment->physical_size();
          uint64_t padding_size = 0x0;
          if (section.file_fixed() and section.file_offset() > segment_end) {
            uint64_t padding_size = section.file_offset() - segment_end;
          }

          // Create the added section
          Section* new_section = new Section{ section };

          // Rebase the new section
          if (section.file_fixed()) {
            new_section->datahandler_ = this->datahandler_;

            new_section->file_offset(section.file_offset());
            DataHandler::Node new_node{
              new_section->file_offset(),
              section_file_size,
              DataHandler::Node::SECTION };
            this->datahandler_->add(new_node);
          }
          if (section.memory_fixed()) {
            new_section->virtual_address(section.virtual_address());
          }

          if (section_is_bss) {
            segment->virtual_size(segment->virtual_size() + section.size());
          } else {
            // Concat the segment data, padding if needed, and the section data
            std::vector<uint8_t> new_content = std::move(segment->content());
            const std::vector<uint8_t>& section_content = section.content();
            new_content.reserve(new_content.size() + padding_size + section_content.size());

            if (padding_size > 0) {
              const std::vector<uint8_t>& padding = std::vector<uint8_t>(padding_size, uint8_t());
              std::move(std::begin(padding), std::end(padding), std::back_inserter(new_content));
            }

            std::move(std::begin(section_content), std::end(section_content), std::back_inserter(new_content));

            // We must update the physical size before updating the content to avoid a warning
            segment->physical_size(new_content.size());
            segment->virtual_size(align(new_content.size(), segment->alignment()));
            segment->content(new_content);
          }

          new_section->segments_.push_back(segment);
          this->header().numberof_sections(this->header().numberof_sections() + 1);
          this->sections_.push_back(new_section);
          segment->sections_.push_back(new_section);
          return *(this->sections_.back());
        }
      }

    // Create a new Segment
    Segment new_segment;
    new_segment.content(section.content());
    new_segment.type(segment_type);

    if (section.file_fixed()) {
      new_segment.file_offset(section.file_offset());
    }
    if (section.memory_fixed()) {
      new_segment.virtual_address(section.virtual_address());
    }
    if (section_is_bss) {
      new_segment.virtual_size(section.size());
    } else {
      new_segment.physical_size(section.size());
    }
    new_segment.alignment(section.alignment());
    new_segment.flags(segment_flags);

    Segment& segment_added = this->add(new_segment);
    //if (section.memory_fixed()) {
    //  segment_added.virtual_address(section.virtual_address());
    //}

    // TODO: describe why
    //if (!section.file_fixed()) {
    //  segment_added.file_fixed(false);
    //}
    //if (!section.memory_fixed()) {
    //  segment_added.memory_fixed(false);
    //}

    VLOG(VDEBUG) << "Segment associated: '" << segment_added << "'";

    Section* new_section = new Section{ section };

    if (section.file_fixed()) {
      new_section->datahandler_ = this->datahandler_;
      DataHandler::Node new_node{
              new_section->file_offset(),
              new_section->size(),
              DataHandler::Node::SECTION };
      this->datahandler_->add(new_node);
    }

    if (section.file_fixed()) {
      new_section->offset(segment_added.file_offset());
    }
    if (section.memory_fixed()) {
      new_section->virtual_address(segment_added.virtual_address());
    }
    new_section->size(segment_added.physical_size());
    new_section->original_size_ = segment_added.physical_size();
    new_section->segments_.push_back(&segment_added);
    segment_added.sections_.push_back(new_section);

    this->header().numberof_sections(this->header().numberof_sections() + 1);

    this->sections_.push_back(new_section);
    return *(this->sections_.back());
  }


  // ============
  // ET_LIEF_CORE
  // ============
  template<>
  Segment& Binary::add_segment<E_TYPE::ET_LIEF_CORE>(const Segment & segment, uint64_t base) {
    Header& header = this->header();

    //uint64_t last_offset_sections = std::accumulate(
    //  std::begin(this->sections_),
    //  std::end(this->sections_), 0,
    //  [](uint64_t offset, const Section * section) {
    //    return std::max<uint64_t>(section->file_offset() + section->size(), offset);
    //  });

    //uint64_t last_offset_segments = std::accumulate(
    //  std::begin(this->segments_),
    //  std::end(this->segments_), 0,
    //  [](uint64_t offset, const Segment * segment) {
    //    return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
    //  });

    //uint64_t last_offset = std::max<uint64_t>(last_offset_sections, last_offset_segments);
    //uint64_t new_phdr_offset = last_offset;

    header.numberof_segments(header.numberof_segments() + 1);

    //uint64_t phdr_size = 0;
    //if (this->type() == ELF_CLASS::ELFCLASS32) {
    //  phdr_size = sizeof(ELF32::Elf_Phdr);
    //}

    //if (this->type() == ELF_CLASS::ELFCLASS64) {
    //  phdr_size = sizeof(ELF64::Elf_Phdr);
    //}


    std::vector<uint8_t> content = segment.content();
    Segment* new_segment = new Segment{ segment };

    if (new_segment->file_fixed()) {
      new_segment->datahandler_ = this->datahandler_;

      DataHandler::Node new_node{
              new_segment->file_offset(),
              new_segment->physical_size(),
              DataHandler::Node::SEGMENT };
      this->datahandler_->add(new_node);
    }

    const uint64_t psize = static_cast<uint64_t>(getpagesize());
    //const uint64_t last_offset_aligned = align(last_offset, psize);

    //new_segment->file_offset(last_offset_aligned);
    //if (segment.virtual_address() == 0) {
    //  new_segment->virtual_address(base + last_offset_aligned);
    //}

    //new_segment->physical_address(new_segment->virtual_address());

    uint64_t segmentsize = align(content.size(), psize);
    content.resize(segmentsize, 0);

    new_segment->physical_size(segmentsize);
    new_segment->virtual_size(segmentsize);

    if (new_segment->alignment() == 0) {
      new_segment->alignment(psize);
    }

    //this->datahandler_->make_hole(last_offset_aligned, new_segment->physical_size());
    new_segment->content(content);

    //if (header.section_headers_offset() <= new_segment->file_offset() + new_segment->physical_size()) {
    //
    //header.section_headers_offset(header.section_headers_offset() + new_phdr_offset + phdr_size * header.numberof_segments());
    //header.section_headers_offset(header.section_headers_offset() + new_segment->file_offset() + new_segment->physical_size() + phdr_size);

    //}

    //if (header.program_headers_offset() <= new_segment->file_offset() + new_segment->physical_size()) {
    //header.program_headers_offset(header.program_headers_offset() + new_segment->file_offset() + new_segment->physical_size());
    //}

    auto && it_new_segment_place = std::find_if(
      this->segments_.rbegin(),
      this->segments_.rend(),
      [&new_segment](const Segment * s) {
        return s->type() == new_segment->type();
      });

    if (it_new_segment_place == this->segments_.rend()) {
      this->segments_.push_back(new_segment);
    }
    else {
      const size_t idx = std::distance(std::begin(this->segments_), it_new_segment_place.base());
      this->segments_.insert(std::begin(this->segments_) + idx, new_segment);
    }

    return *new_segment;

  }


  template<class T>
  std::unique_ptr<Binary> Binary::create_lief_core_impl(ARCH arch, ELF_CLASS clazz) {
    using Elf_Phdr = typename T::Elf_Phdr;
    using Elf_Ehdr = typename T::Elf_Ehdr;
    using Elf_Shdr = typename T::Elf_Shdr;

    std::unique_ptr<Binary> new_binary{ new Binary{} };
    new_binary->type_ = clazz;

    // Set header
    new_binary->header_.file_type(E_TYPE::ET_LIEF_CORE);
    new_binary->header_.machine_type(arch);
    new_binary->header_.object_file_version(VERSION::EV_CURRENT);
    new_binary->header_.entrypoint(0);


    new_binary->header_.processor_flag(0);

    new_binary->header_.header_size(sizeof(Elf_Ehdr));
    new_binary->header_.program_header_size(sizeof(Elf_Phdr));
    new_binary->header_.section_header_size(sizeof(Elf_Shdr));

    std::string ident = "\x7F";
    new_binary->header_.identity(ident + "ELF");
    new_binary->header_.identity_class(clazz);
    new_binary->header_.identity_data(ELF_DATA::ELFDATA2LSB);
    new_binary->header_.identity_version(VERSION::EV_CURRENT);
    new_binary->header_.identity_os_abi(OS_ABI::ELFOSABI_SYSTEMV);


    new_binary->datahandler_ = new DataHandler::Handler{ std::vector<uint8_t>{} };

    size_t cursor = sizeof(Elf_Ehdr);
    // Add new null entry section

    Section * null_section = new Section{ "", ELF_SECTION_TYPES::SHT_NULL };
    null_section->datahandler_ = new_binary->datahandler_;
    new_binary->datahandler_->add({ null_section->file_offset(), null_section->size(), DataHandler::Node::SECTION });

    new_binary->sections_.push_back(null_section);

    Section * shstrtab = new Section{ ".shstrtab", ELF_SECTION_TYPES::SHT_STRTAB };
    shstrtab->offset(cursor);

    shstrtab->datahandler_ = new_binary->datahandler_;
    new_binary->datahandler_->add({ shstrtab->file_offset(), 0, DataHandler::Node::SECTION });
    shstrtab->size(100);
    cursor += shstrtab->size();
    new_binary->sections_.push_back(shstrtab);
    new_binary->datahandler_->make_hole(shstrtab->file_offset(), shstrtab->size());

    new_binary->header_.program_headers_offset(cursor);
    cursor += 1;

    new_binary->header_.section_headers_offset(cursor);
    new_binary->header_.section_name_table_idx(new_binary->sections_.size() - 1);

    const size_t shdr_sizes = (new_binary->sections_.size() + 1) * sizeof(Elf_Shdr);
    cursor += shdr_sizes;

    new_binary->header().numberof_sections(new_binary->sections_.size());
    new_binary->header().numberof_segments(new_binary->segments_.size());
    return new_binary;
  }

}
}
