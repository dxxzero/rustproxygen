use windows::Win32::System::Diagnostics::Debug::IMAGE_DATA_DIRECTORY;
use windows::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER;
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE;
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;
use windows::Win32::System::SystemServices::IMAGE_NT_SIGNATURE;

pub fn parse(data: Vec<u8>) -> PE {
    PE::build(data)
}


struct ExportTableData {
    num_of_sections: u16,
    section_table_offset: usize,
    export_table_data: IMAGE_DATA_DIRECTORY
}

#[derive(Default)]
pub struct ExportTable {
    pub array_of_names: Vec<String>,
    pub array_of_ordinals: Vec<u32>,
}

pub struct PE {
    pub x64: bool,
    pub dos_header: IMAGE_DOS_HEADER,
    pub nt_headers_x86: IMAGE_NT_HEADERS32,
    pub nt_headers_x64: IMAGE_NT_HEADERS64,
    pub data: Vec<u8>,
    pub export_table: ExportTable
}

impl PE {
    fn build(data: Vec<u8>) -> PE {
        let dos_header = unsafe { *data.as_ptr().cast::<IMAGE_DOS_HEADER>() };
        let bitness = unsafe { *(data.as_ptr().add(dos_header.e_lfanew as usize + 0x18).cast::<u16>())};
        let nt_headers_x64: IMAGE_NT_HEADERS64;
        let nt_headers_x86: IMAGE_NT_HEADERS32;
        let x64;

        if bitness == 0x20b {
            nt_headers_x64 = unsafe { *(data.as_ptr().add(dos_header.e_lfanew as usize).cast::<IMAGE_NT_HEADERS64>())};
            nt_headers_x86 = Default::default();
            x64 = true;
        } else if bitness == 0x10b {
            nt_headers_x64 = Default::default();
            nt_headers_x86 = unsafe { *(data.as_ptr().add(dos_header.e_lfanew as usize).cast::<IMAGE_NT_HEADERS32>())};
            x64 = false;
        } else {
            panic!("Unknown Architecture!");
        }

        if dos_header.e_magic != IMAGE_DOS_SIGNATURE || (nt_headers_x64.Signature != IMAGE_NT_SIGNATURE && nt_headers_x86.Signature != IMAGE_NT_SIGNATURE) {
            panic!("Invalid binary file!");
        }

        let mut pe = PE {dos_header, x64, nt_headers_x64, nt_headers_x86, data, export_table: Default::default()};

        let export_table = pe.create_export_table();

        pe.export_table = export_table;

        pe
    }

    fn create_export_table(&self) -> ExportTable {
        let export_table_data = self.get_export_table_data();
        let export_table_offset = self.rva_to_offset(&export_table_data, export_table_data.export_table_data.VirtualAddress);
        let export_table = unsafe { *(self.data.as_ptr().add(export_table_offset as usize).cast::<IMAGE_EXPORT_DIRECTORY>())};

        let address_of_names_offset = self.rva_to_offset(&export_table_data, export_table.AddressOfNames);
        let export_names_array = self.create_export_array(address_of_names_offset as usize, export_table.NumberOfNames, &export_table_data);

        let address_of_ordinals_offset = self.rva_to_offset(&export_table_data, export_table.AddressOfNameOrdinals);
        let export_ordinals_array = self.create_ordinals_array(address_of_ordinals_offset as usize, export_table.NumberOfFunctions, export_table.Base);

        ExportTable {array_of_names: export_names_array, array_of_ordinals: export_ordinals_array}
    }

    fn get_export_table_data(&self) -> ExportTableData {
        let num_of_sections;
        let section_table_offset;
        let export_table_data;

        if self.x64 {
            export_table_data = self.nt_headers_x64.OptionalHeader.DataDirectory[0];
            num_of_sections = self.nt_headers_x64.FileHeader.NumberOfSections;
            section_table_offset = std::mem::size_of::<u32>() + std::mem::size_of::<IMAGE_FILE_HEADER>() + self.nt_headers_x64.FileHeader.SizeOfOptionalHeader as usize;
        } else {
            export_table_data = self.nt_headers_x86.OptionalHeader.DataDirectory[0];
            num_of_sections = self.nt_headers_x86.FileHeader.NumberOfSections;
            section_table_offset = std::mem::size_of::<u32>() + std::mem::size_of::<IMAGE_FILE_HEADER>() + self.nt_headers_x86.FileHeader.SizeOfOptionalHeader as usize;
        }

        ExportTableData {num_of_sections, section_table_offset, export_table_data}
    }

    fn create_export_array(&self, address_of_names_array_offset: usize, number_of_names: u32, export_table_data: &ExportTableData) -> Vec<String> {
        let mut export_array: Vec<String> = Default::default();
        
        for i in (0..number_of_names*4).step_by(4) {
            let tmp_i = i as usize;
            let name_rva = ((self.data[address_of_names_array_offset + tmp_i + 3] as u32) << 24)
                        | (self.data[address_of_names_array_offset + tmp_i + 2] as u32) << 16
                        | (self.data[address_of_names_array_offset + tmp_i + 1] as u32) << 8
                        | self.data[address_of_names_array_offset + tmp_i] as u32;
            let name_offset = self.rva_to_offset(&export_table_data, name_rva);
            let name = self.parse_name(name_offset as usize);
            export_array.push(name);
        }

        export_array
    }

    fn parse_name(&self, name_offset: usize) -> String {
        let mut chr = std::char::from_u32(self.data[name_offset] as u32).unwrap();
        let mut current_function = String::from("");
        let mut i: usize = 0;

        while chr != '\0' {
            current_function.push(chr);
            i += 1;
            chr = std::char::from_u32(self.data[name_offset + i] as u32).unwrap();
        }

        current_function
    }

    fn create_ordinals_array(&self, address_of_ordinals_offset: usize, num_of_functions: u32, base: u32) -> Vec<u32> {
        let mut export_array: Vec<u32> = Default::default();

        for i in (0..(num_of_functions * 2)).step_by(2) {
            let ordinal = ((self.data[address_of_ordinals_offset + i as usize + 1] as u16) << 8) | self.data[address_of_ordinals_offset + i as usize] as u16;
            export_array.push(ordinal as u32 + base);
        }
        
        export_array
    }

    fn rva_to_offset(&self, export_table_data: &ExportTableData, rva: u32) -> u32 {
        for i in 0..export_table_data.num_of_sections {
            let section_header_offset = self.dos_header.e_lfanew as usize
            + export_table_data.section_table_offset
            + std::mem::size_of::<IMAGE_SECTION_HEADER>() * (i as usize);

            let section_header = unsafe { *(self.data.as_ptr().add(section_header_offset).cast::<IMAGE_SECTION_HEADER>())};
            let end_of_header = section_header.VirtualAddress + section_header.SizeOfRawData;
            if end_of_header >= rva {
                return rva - section_header.VirtualAddress + section_header.PointerToRawData;
            }
        }

        panic!("Could not find correct section!");   //TODO throw exception
    }

}